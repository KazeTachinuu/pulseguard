package tui

import (
	"errors"
	"fmt"

	"github.com/jroimartin/gocui"
)

// Run launches a minimal gocui-based interface and blocks until the user exits.
func Run() error {
	gui, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		return fmt.Errorf("create gui: %w", err)
	}
	defer gui.Close()

	gui.SetManagerFunc(func(g *gocui.Gui) error {
		const (
			width  = 34
			height = 5
		)
		maxX, maxY := g.Size()
		x0 := (maxX - width) / 2
		y0 := (maxY - height) / 2
		x1 := x0 + width
		y1 := y0 + height

		v, err := g.SetView("hello", x0, y0, x1, y1)
		if err != nil {
			if !errors.Is(err, gocui.ErrUnknownView) {
				return err
			}
			v.Title = "PulseGuard"
			v.Wrap = true
			fmt.Fprintln(v, "Hello from PulseGuard!")
			fmt.Fprintln(v, "Press q or Ctrl+C to exit.")
		}
		return nil
	})

	quit := func(*gocui.Gui, *gocui.View) error {
		return gocui.ErrQuit
	}

	if err := gui.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		return fmt.Errorf("bind ctrl+c: %w", err)
	}
	if err := gui.SetKeybinding("", 'q', gocui.ModNone, quit); err != nil {
		return fmt.Errorf("bind q: %w", err)
	}

	if err := gui.MainLoop(); err != nil && err != gocui.ErrQuit {
		return fmt.Errorf("main loop: %w", err)
	}
	return nil
}
