package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/agentveil/agentveil/internal/desktopapp"
	"github.com/agentveil/agentveil/internal/instance"
)

const monitorInterval = 3 * time.Second

func main() {
	application := app.NewWithID("com.agentveil.desktop")
	icon := fyne.NewStaticResource("agentveil.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><path fill="#5b5bd6" d="M32 3 55 12v17c0 15-9 26-23 32C18 55 9 44 9 29V12z"/><path fill="white" d="M19 31h26v18H19zm4-4a9 9 0 0 1 18 0v6h-5v-6a4 4 0 0 0-8 0v6h-5z"/></svg>`))
	application.SetIcon(icon)
	window := application.NewWindow("AgentVeil")
	window.Resize(fyne.NewSize(560, 360))

	supervisor, autoStart, executable, desktopLock, err := configureDesktop()
	if err != nil {
		window.SetContent(container.NewCenter(widget.NewLabel("AgentVeil could not start: " + err.Error())))
		window.ShowAndRun()
		return
	}
	defer desktopLock.Close()

	ctx, cancel := context.WithCancel(context.Background())
	statusText := binding.NewString()
	_ = statusText.Set("Starting Privacy Core…")
	statusLabel := widget.NewLabelWithData(statusText)
	statusLabel.Wrapping = fyne.TextWrapWord
	token := widget.NewPasswordEntry()
	token.SetText(supervisor.Token())
	token.Disable()

	openDashboard := func() {
		status := supervisor.Status()
		if !status.Running || status.Endpoint == "" {
			_ = statusText.Set("Privacy Core is not ready")
			return
		}
		target, parseErr := url.Parse(status.Endpoint + "/")
		if parseErr != nil || application.OpenURL(target) != nil {
			_ = statusText.Set("Dashboard could not be opened")
		}
	}
	autostartCheck := widget.NewCheck("Start AgentVeil when I sign in", func(enabled bool) {
		if err := autoStart.Set(enabled, executable); err != nil {
			_ = statusText.Set("Could not update startup setting: " + err.Error())
		}
	})
	autostartCheck.SetChecked(autoStart.Enabled())

	window.SetContent(container.NewVBox(
		widget.NewLabelWithStyle("AgentVeil Privacy Core", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		statusLabel,
		widget.NewSeparator(),
		widget.NewLabel("Dashboard management token"),
		token,
		container.NewHBox(
			widget.NewButton("Copy token", func() { window.Clipboard().SetContent(supervisor.Token()) }),
			widget.NewButton("Open Dashboard", openDashboard),
		),
		layout.NewSpacer(),
		autostartCheck,
		widget.NewLabel("Closing this window keeps protection running. Use Quit from the tray to exit AgentVeil; an active Core Session is never terminated."),
	))
	window.SetCloseIntercept(window.Hide)

	quit := func() {
		shutdownContext, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		stopped, stopErr := supervisor.StopIfIdle(shutdownContext)
		if stopErr != nil {
			application.SendNotification(&fyne.Notification{Title: "AgentVeil", Content: "Privacy Core could not be stopped safely."})
		} else if !stopped && supervisor.Status().Owned && supervisor.Status().Sessions > 0 {
			application.SendNotification(&fyne.Notification{Title: "AgentVeil", Content: "Privacy Core remains active because protected Sessions are running."})
			return
		}
		cancel()
		application.Quit()
	}
	if tray, ok := application.(desktop.App); ok {
		tray.SetSystemTrayIcon(icon)
		tray.SetSystemTrayWindow(window)
		tray.SetSystemTrayMenu(fyne.NewMenu("AgentVeil",
			fyne.NewMenuItem("Show AgentVeil", window.Show),
			fyne.NewMenuItem("Open Dashboard", openDashboard),
			fyne.NewMenuItem("Quit", quit),
		))
	}

	go monitorCore(ctx, application, supervisor, statusText)
	window.ShowAndRun()
}

func configureDesktop() (*desktopapp.Supervisor, desktopapp.AutoStart, string, *instance.Lock, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, desktopapp.AutoStart{}, "", nil, err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return nil, desktopapp.AutoStart{}, "", nil, err
	}
	coreExecutable := os.Getenv("VEIL_CORE_EXECUTABLE")
	if coreExecutable == "" {
		name := "veil"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		coreExecutable = filepath.Join(filepath.Dir(executable), name)
	}
	configRoot, err := os.UserConfigDir()
	if err != nil {
		return nil, desktopapp.AutoStart{}, "", nil, err
	}
	configDir := filepath.Join(configRoot, "agentveil")
	desktopLock, err := instance.Acquire(filepath.Join(configDir, "desktop.lock"))
	if err != nil {
		return nil, desktopapp.AutoStart{}, "", nil, err
	}
	token := os.Getenv("VEIL_ADMIN_TOKEN")
	if token == "" {
		token, err = desktopapp.LoadOrCreateToken(configDir)
		if err != nil {
			desktopLock.Close()
			return nil, desktopapp.AutoStart{}, "", nil, err
		}
	}
	autoStart, err := desktopapp.DefaultAutoStart()
	if err != nil {
		desktopLock.Close()
		return nil, desktopapp.AutoStart{}, "", nil, err
	}
	supervisor, err := desktopapp.NewSupervisor(desktopapp.Options{CoreExecutable: coreExecutable, ConfigDir: configDir, ManagementToken: token, ReadyTimeout: 10 * time.Second})
	if err != nil {
		desktopLock.Close()
		return nil, desktopapp.AutoStart{}, "", nil, err
	}
	return supervisor, autoStart, executable, desktopLock, nil
}

func monitorCore(ctx context.Context, application fyne.App, supervisor *desktopapp.Supervisor, statusText binding.String) {
	wasHealthy := false
	for {
		status, err := supervisor.Ensure(ctx)
		if err == nil {
			_ = statusText.Set(fmt.Sprintf("Privacy Core is running at %s · %d active Sessions", status.Endpoint, status.Sessions))
			if !wasHealthy {
				application.SendNotification(&fyne.Notification{Title: "AgentVeil", Content: "Privacy Core is ready."})
			}
			wasHealthy = true
		} else if ctx.Err() == nil {
			_ = statusText.Set("Privacy Core unavailable; retrying safely: " + err.Error())
			wasHealthy = false
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(monitorInterval):
			if _, err := supervisor.Check(ctx); err != nil {
				wasHealthy = false
			}
		}
	}
}
