// Package tray renders the redactr menubar (macOS) and reflects daemon/proxy
// state. The state→view mapping is a pure function (TrayState) for testability;
// the systray glue lives in tray_systray.go.
package tray

import "github.com/rakeshguha/redactr/internal/control"

// View is the rendered tray state.
type View struct {
	Color      string // "green" | "red"
	ProxyLabel string
}

// TrayState maps a daemon status (and whether the daemon was reachable) to the
// menubar view. Green only when the daemon is reachable and the proxy is live.
func TrayState(st control.Status, reachable bool) View {
	if !reachable {
		return View{Color: "red", ProxyLabel: "Daemon: Down"}
	}
	if st.Proxy.Enabled && st.Proxy.Addr != "" {
		return View{Color: "green", ProxyLabel: "Proxy: Enabled"}
	}
	return View{Color: "red", ProxyLabel: "Proxy: Disabled"}
}
