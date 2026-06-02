//go:build darwin || windows

package tray

import (
	"time"

	"fyne.io/systray"

	"github.com/rakeshguha/redactr/internal/cli"
)

// Run starts the menubar/notification-area event loop. It blocks (systray.Run
// owns the main thread); callers must invoke it from main.
func Run(sockDir string) {
	client := cli.NewClient(sockDir)
	systray.Run(func() { onReady(client) }, func() {})
}

func onReady(client *cli.Client) {
	systray.SetIcon(iconBytes("red"))
	systray.SetTooltip("redactr — Proxy: …")
	mToggle := systray.AddMenuItem("Proxy: …", "Toggle the redactr proxy")
	mQuit := systray.AddMenuItem("Quit", "Quit redactr tray")

	apply := func() {
		st, err := client.Status()
		v := TrayState(st, err == nil)
		systray.SetIcon(iconBytes(v.Color))
		systray.SetTooltip("redactr — " + v.ProxyLabel)
		mToggle.SetTitle(v.ProxyLabel)
	}
	apply()

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				apply()
			case <-mToggle.ClickedCh:
				if st, err := client.Status(); err == nil && st.Proxy.Enabled {
					_, _ = client.DisableProxy()
				} else {
					_, _ = client.EnableProxy()
				}
				apply()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}
