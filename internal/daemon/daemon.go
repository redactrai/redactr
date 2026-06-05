// Package daemon is the Redactr control/policy plane: it wires and supervises
// the proxy, scanner, dashboard, admin, firewall, sidecar, and control socket.
// It is the extracted form of what used to be cmd/redactr/main.go's main().
package daemon

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/redactrai/redactr/internal/admin"
	"github.com/redactrai/redactr/internal/api"
	"github.com/redactrai/redactr/internal/certgen"
	"github.com/redactrai/redactr/internal/cli"
	"github.com/redactrai/redactr/internal/config"
	"github.com/redactrai/redactr/internal/coordinator"
	"github.com/redactrai/redactr/internal/domain"
	"github.com/redactrai/redactr/internal/enrollment"
	"github.com/redactrai/redactr/internal/fileblock"
	"github.com/redactrai/redactr/internal/firewall"
	"github.com/redactrai/redactr/internal/licensing"
	"github.com/redactrai/redactr/internal/lifecycle"
	"github.com/redactrai/redactr/internal/logging"
	"github.com/redactrai/redactr/internal/monitor"
	"github.com/redactrai/redactr/internal/policysync"
	"github.com/redactrai/redactr/internal/proxy"
	"github.com/redactrai/redactr/internal/rules"
	"github.com/redactrai/redactr/internal/scanner"
	"github.com/redactrai/redactr/internal/scanner/contextgate"
	"github.com/redactrai/redactr/internal/scanner/entropy"
	"github.com/redactrai/redactr/internal/scanner/gliner"
	"github.com/redactrai/redactr/internal/scanner/presidio"
	"github.com/redactrai/redactr/internal/sessions"
	"github.com/redactrai/redactr/internal/shipper"
	"github.com/redactrai/redactr/internal/sidecar"
	"github.com/redactrai/redactr/internal/store"
)

// Options parameterizes Build. Ephemeral is set by tests to bind admin +
// dashboard on OS-assigned ports; production leaves it false so the v1 ports
// (admin = cfg.Admin.Port, dashboard = 9080) are preserved exactly.
type Options struct {
	BaseDir   string
	Ephemeral bool
}

// Daemon holds every long-lived component constructed in Build and used later
// in Start/Stop. It is the struct-ified form of main()'s local variables.
type Daemon struct {
	opts Options

	cfgMgr        *config.Manager
	lock          *lifecycle.Lock
	licMgr        *licensing.Manager
	ca            *certgen.CA
	store         *store.Store
	pipeline      *scanner.Pipeline
	coord         *coordinator.Coordinator
	glinerClient  *gliner.Client
	adminServer   *admin.Server
	domainFilter  *domain.Filter
	hub           *api.Hub
	proxy         *proxy.Proxy
	apiServer     *api.Server
	fwMgr         firewall.Manager
	fwController  *firewall.Controller
	sidecarMgr    *sidecar.Manager
	configWatcher *config.Watcher

	transparentAddr string
	dashboardAddr   string
	adminAddr       string

	sessLister      *sessions.Lister
	reconcileCancel context.CancelFunc
	policyCancel    context.CancelFunc
	monitorCancel   context.CancelFunc
	shipperCancel   context.CancelFunc
	// shipEnabled is true exactly while the shipper goroutine is running (set in
	// Start when enrolled + non-ephemeral). onScan checks it so audit records are
	// only enqueued when there is a shipper to drain them.
	shipEnabled atomic.Bool
	sock        *http.Server // B3: control socket lives here
}

// Build wires up all daemon components without starting any listeners. It is
// the extracted form of main()'s body from config load through fwController +
// configWatcher construction. Every former log.Fatalf becomes a returned error.
func Build(opts Options) (*Daemon, error) {
	baseDir := opts.BaseDir
	os.MkdirAll(filepath.Join(baseDir, "certs"), 0755)
	os.MkdirAll(filepath.Join(baseDir, "data"), 0755)
	os.MkdirAll(filepath.Join(baseDir, "state"), 0755)

	d := &Daemon{opts: opts}

	cfgMgr, err := config.NewManager(filepath.Join(baseDir, "config.yaml"))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	d.cfgMgr = cfgMgr
	cfg := cfgMgr.Get()

	// One-time migration: translate legacy layer flags into per-rule entries.
	if err := cfgMgr.Update(func(c *config.Config) {
		config.MigrateLegacyLayerFlagsFromFile(&c.Scanning, filepath.Join(baseDir, "config.yaml"))
	}); err != nil {
		log.Printf("config migration warning: %v", err)
	}
	cfg = cfgMgr.Get()

	eff := rules.Effective(cfg.Scanning.Rules)
	ruleEnabled := func(id string) bool { return eff[id] }

	if _, err := logging.Setup(logging.Config{
		Level:  cfg.Logging.Level,
		Output: cfg.Logging.Output,
	}); err != nil {
		return nil, fmt.Errorf("logging: %w", err)
	}

	stateDir := filepath.Join(baseDir, "state")
	lock, err := lifecycle.AcquireSingleton(stateDir, slog.Default(), lifecycle.Options{})
	if err != nil {
		return nil, fmt.Errorf("lifecycle: %w", err)
	}
	d.lock = lock

	licMgr, err := licensing.NewManager(licensing.DevPublicKey, cfg.Licensing.Key)
	if err != nil {
		return nil, fmt.Errorf("licensing: %w", err)
	}
	d.licMgr = licMgr

	ca, err := certgen.LoadOrCreateCA(
		filepath.Join(baseDir, "certs", "ca.crt"),
		filepath.Join(baseDir, "certs", "ca.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("CA: %w", err)
	}
	d.ca = ca

	logStore, err := store.New(filepath.Join(baseDir, "data", "logs.db"))
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	d.store = logStore

	presidioScanner := presidio.NewWithEnabled(ruleEnabled)
	entropyScanner := entropy.New(cfg.Scanning.EntropyThreshold, 20)
	entropyScanner.SetEnabled(eff["entropy_keyword_gated"], eff["entropy_unconditional"])
	glinerClient := gliner.New("http://127.0.0.1:0")
	glinerClient.Reconfigure(ruleEnabled)
	d.glinerClient = glinerClient
	contextGate := contextgate.New()

	pipeline := scanner.NewPipeline(presidioScanner, entropyScanner, glinerClient, contextGate)
	pipeline.SetTimeout(cfg.Scanning.InferenceTimeoutMs)
	d.pipeline = pipeline
	cache := scanner.NewCache(cfg.Scanning.CacheMaxSize)
	fbExts, fbContentPatterns := rules.FileBlockExtensions(
		cfg.FileBlocking.BlockedExtensions,
		eff,
		cfg.FileBlocking.ContentPatternsEnabled,
	)
	fb := fileblock.New(fbExts, fbContentPatterns)
	coord := coordinator.New(pipeline, cache, fb)
	if len(cfg.Scanning.AllowedWords) > 0 {
		coord.SetAllowedWords(cfg.Scanning.AllowedWords)
	}
	d.coord = coord

	adminServer := admin.NewServer([]admin.LayerChecker{presidioScanner, entropyScanner, glinerClient, contextGate})
	d.adminServer = adminServer

	domainFilter := domain.New(cfg.Proxy.InterceptedDomains, cfg.Proxy.BlockedDomains)
	d.domainFilter = domainFilter

	hub := api.NewHub()
	go hub.Run()
	d.hub = hub

	onScan := func(report *store.ScanReport) {
		logStore.SaveReport(report)
		hub.Broadcast(report)
		if d.shipEnabled.Load() {
			for _, a := range auditRecordsFromReport(report) {
				if err := logStore.EnqueueAudit(a); err != nil {
					slog.Warn("audit enqueue failed", "error", err)
				}
			}
		}
	}

	bypassMatcher := proxy.NewBypassMatcher(cfg.Scanning.Bypass)
	p, err := proxy.NewProxy(ca, domainFilter, coord, bypassMatcher, onScan)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	d.proxy = p

	apiServer := api.NewServer(cfgMgr, logStore, p, coord, hub)
	d.apiServer = apiServer

	apiServer.SetLicense(licMgr)
	d.sessLister = sessions.New(os.Getpid())
	apiServer.SetSessions(d.sessLister)
	if exe, err := cli.Self(); err == nil {
		apiServer.SetRedactrBinary(exe)
	} else {
		slog.Warn("could not resolve redactr binary path", "error", err)
	}

	// Firewall Controller — needed for "Enable Proxy" to actually route traffic.
	fwMgr, err := firewall.New()
	if err != nil {
		return nil, fmt.Errorf("firewall: %w", err)
	}
	d.fwMgr = fwMgr
	firewall.SetCAPath(filepath.Join(baseDir, "certs", "ca.crt"))

	// Ephemeral (test) mode skips orphan reaping — it touches host firewall
	// state (osascript) and is meaningless for a throwaway baseDir.
	if !opts.Ephemeral {
		if err := lifecycle.ReapOrphans(stateDir, fwMgr, slog.Default()); err != nil {
			slog.Warn("orphan reap had errors", "event", "lifecycle_reap_warn", "error", err.Error())
		}
	}

	statePath := filepath.Join(baseDir, "state", "firewall.json")
	fwController := firewall.NewController(fwMgr, firewall.DefaultResolver, statePath)
	d.fwController = fwController

	sidecarScript := filepath.Join(baseDir, "..", "sidecar", "gliner", "server.py")
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "..", "sidecar", "gliner", "server.py")
		if _, err := os.Stat(candidate); err == nil {
			sidecarScript = candidate
		}
	}
	if wd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(wd, "sidecar", "gliner", "server.py")
		if _, err := os.Stat(candidate); err == nil {
			sidecarScript = candidate
		}
	}
	sidecarMgr := sidecar.NewManager(
		"python3",
		sidecarScript,
		filepath.Join(baseDir, "state"),
	)
	d.sidecarMgr = sidecarMgr

	configWatcher := config.NewWatcher(cfgMgr, func(newCfg *config.Config) {
		newEff := rules.Effective(newCfg.Scanning.Rules)
		newEnabled := func(id string) bool { return newEff[id] }
		fbExtsNew, fbContentNew := rules.FileBlockExtensions(
			newCfg.FileBlocking.BlockedExtensions,
			newEff,
			newCfg.FileBlocking.ContentPatternsEnabled,
		)
		coord.Reconfigure(newEnabled, fbExtsNew, fbContentNew)

		coord.SetAllowedWords(newCfg.Scanning.AllowedWords)

		pipeline.SetTimeout(newCfg.Scanning.InferenceTimeoutMs)

		bypassMatcher.SetRules(newCfg.Scanning.Bypass)

		if _, err := logging.Setup(logging.Config{
			Level:  newCfg.Logging.Level,
			Output: newCfg.Logging.Output,
		}); err != nil {
			slog.Warn("failed to update log level", "error", err)
		}
	})
	d.configWatcher = configWatcher

	return d, nil
}

// Start brings up the listeners and the reconcile loop. It is the extracted
// form of main()'s body from adminServer.Start through proxy.Start. Every
// former log.Fatalf becomes a returned error.
func (d *Daemon) Start() error {
	baseDir := d.opts.BaseDir
	cfg := d.cfgMgr.Get()
	adminPort := cfg.Admin.Port
	dashPort := 9080
	if d.opts.Ephemeral {
		adminPort, dashPort = 0, 0
	}

	adminAddr, err := d.adminServer.Start(adminPort)
	if err != nil {
		return fmt.Errorf("admin: %w", err)
	}
	d.adminAddr = adminAddr

	// Start transparent listener.
	transparentAddr, err := d.proxy.StartTransparent(0)
	if err != nil {
		return fmt.Errorf("transparent listener: %w", err)
	}
	d.transparentAddr = transparentAddr
	log.Printf("Transparent listener: %s", transparentAddr)

	d.apiServer.SetFirewall(d.fwController, transparentAddr)

	// 5-minute reconcile loop.
	reconcileCtx, reconcileCancel := context.WithCancel(context.Background())
	d.reconcileCancel = reconcileCancel
	go d.fwController.RunReconcileLoop(reconcileCtx, 5*time.Minute)

	dashboardAddr, err := d.apiServer.Start(dashPort)
	if err != nil {
		return fmt.Errorf("dashboard: %w", err)
	}
	d.dashboardAddr = dashboardAddr
	os.WriteFile(filepath.Join(baseDir, "state", "dashboard.port"), []byte(dashboardAddr), 0644)

	eff := rules.Effective(cfg.Scanning.Rules)
	glinerEnabled := func() bool {
		for _, r := range rules.AllRules() {
			if r.Layer == "gliner" && eff[r.ID] {
				return true
			}
		}
		return false
	}()
	// Ephemeral (test) mode skips the external python sidecar to stay hermetic.
	if glinerEnabled && !d.opts.Ephemeral {
		if err := d.sidecarMgr.StartLazy(); err != nil {
			slog.Warn("GLiNER sidecar start failed", "error", err)
		} else {
			d.glinerClient.SetBaseURL(d.sidecarMgr.URL())
			go func() {
				for i := 0; i < 120; i++ {
					if d.glinerClient.HealthCheck() {
						d.glinerClient.SetReady(true)
						slog.Info("GLiNER sidecar ready", "event", "sidecar_ready", "layer", "gliner")
						return
					}
					time.Sleep(1 * time.Second)
				}
				slog.Error("GLiNER sidecar failed to become ready", "event", "sidecar_timeout", "layer", "gliner")
			}()
		}
	}

	if err := d.configWatcher.Start(); err != nil {
		slog.Warn("config watcher failed to start", "error", err)
	}

	slog.Info("redactr started",
		"event", "startup",
		"dashboard", fmt.Sprintf("http://%s", dashboardAddr),
		"admin", fmt.Sprintf("http://%s", adminAddr),
		"ca_cert", filepath.Join(baseDir, "certs", "ca.crt"),
	)

	if cfg.Proxy.Enabled {
		proxyAddr, err := d.proxy.Start(0)
		if err != nil {
			return fmt.Errorf("proxy start: %w", err)
		}
		os.WriteFile(filepath.Join(baseDir, "state", "proxy.pid"), []byte(proxyAddr), 0644)
		slog.Info("proxy listening", "event", "proxy_started", "addr", proxyAddr)
	} else {
		slog.Info("proxy disabled", "event", "proxy_disabled")
	}

	if err := d.startControlSocket(); err != nil {
		return err
	}

	if !d.opts.Ephemeral && isEnrolled(d.opts.BaseDir) {
		policyCtx, policyCancel := context.WithCancel(context.Background())
		d.policyCancel = policyCancel
		go d.policySyncLoop(policyCtx)

		monitorCtx, monitorCancel := context.WithCancel(context.Background())
		d.monitorCancel = monitorCancel
		go d.monitorLoop(monitorCtx)

		shipperCtx, shipperCancel := context.WithCancel(context.Background())
		d.shipperCancel = shipperCancel
		d.shipEnabled.Store(true)
		sh := shipper.New(d.store, shipper.NewHTTPPoster(d.opts.BaseDir))
		go sh.Run(shipperCtx)
	}

	return nil
}

// Stop tears down all components in the reverse order of Start, mirroring the
// signal-handler shutdown block (plus the former main() defers). Fields that
// may be nil because Start ran only partially are guarded.
func (d *Daemon) Stop() error {
	baseDir := d.opts.BaseDir

	slog.Info("shutting down", "event", "shutdown")
	d.stopControlSocket()
	if d.monitorCancel != nil {
		d.monitorCancel()
	}
	d.shipEnabled.Store(false)
	if d.shipperCancel != nil {
		d.shipperCancel()
	}
	if d.policyCancel != nil {
		d.policyCancel()
	}
	if d.reconcileCancel != nil {
		d.reconcileCancel()
	}
	if d.fwController != nil {
		_ = d.fwController.Disable()
	}
	if d.proxy != nil {
		d.proxy.Stop()
	}
	if d.sidecarMgr != nil {
		d.sidecarMgr.Stop()
	}
	if d.adminServer != nil {
		d.adminServer.Stop()
	}
	if d.apiServer != nil {
		d.apiServer.Stop()
	}
	if d.fwMgr != nil {
		d.fwMgr.Cleanup()
	}

	os.Remove(filepath.Join(baseDir, "state", "proxy.pid"))
	os.Remove(filepath.Join(baseDir, "state", "dashboard.port"))
	os.Remove(filepath.Join(baseDir, "state", "api.port"))
	os.Remove(filepath.Join(baseDir, "state", "sidecar.port"))

	// Former main() defers, in reverse declaration order.
	if d.configWatcher != nil {
		d.configWatcher.Stop()
	}
	if d.licMgr != nil {
		d.licMgr.Stop()
	}
	if d.store != nil {
		d.store.Close()
	}
	if d.lock != nil {
		d.lock.Release()
	}

	slog.Info("redactr stopped", "event", "stopped")
	return nil
}

// isEnrolled reports whether this daemon has device enrollment and so should
// run the control-plane background loops (policy sync, monitor telemetry, shipper).
func isEnrolled(baseDir string) bool {
	return enrollment.Exists(baseDir)
}

// policySyncLoop runs an initial sync then ticks every 10 minutes. It exits
// when ctx is cancelled (i.e. when Stop is called). Errors are logged but do
// not terminate the loop — fail-open means the cached policy is kept.
func (d *Daemon) policySyncLoop(ctx context.Context) {
	_ = policysync.Sync(d.opts.BaseDir) // initial sync; fail-open
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := policysync.Sync(d.opts.BaseDir); err != nil {
				slog.Warn("policy sync failed (keeping cached policy)", "error", err)
			}
		}
	}
}

// monitorLoop runs an initial scan+enqueue then ticks every 60 seconds. It exits
// when ctx is cancelled (i.e. when Stop is called). Errors are logged but do
// not terminate the loop — fail-open means the batch is silently dropped.
func (d *Daemon) monitorLoop(ctx context.Context) {
	report := func() {
		list, err := d.sessLister.List()
		if err != nil {
			slog.Warn("session scan failed", "error", err)
			return
		}
		for _, ev := range monitor.Collect(list) {
			if err := d.store.EnqueueMonitor(ev); err != nil {
				slog.Warn("monitor enqueue failed", "error", err)
			}
		}
	}
	report()
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report()
		}
	}
}

// Run is the production entrypoint: build, start, block on SIGINT/SIGTERM, stop.
func Run(baseDir string) error {
	d, err := Build(Options{BaseDir: baseDir})
	if err != nil {
		return err
	}
	if err := d.Start(); err != nil {
		return err
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	return d.Stop()
}
