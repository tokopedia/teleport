/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/net/websocket"

	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/trace"

	"github.com/moby/moby/pkg/term"
)

// PTY is an interface that defines sizing and drawing operations on the local
// PTY. Implementations will either be for native terminal emulators or web
// based terminal emulators.
type PTY interface {
	// Redraw will re-draw what's inside the PTY window.
	Redraw(w *term.Winsize) error

	// GetSize gets the current physical size of the terminal window.
	GetSize() (*term.Winsize, error)

	// SetSize sets the current physical size of the terminal window.
	SetSize(w *term.Winsize)
}

// NativePTY represents a native terminal emulator like GNOME Terminal (Linux)
// or Terminal.app (macOS).
type NativePTY struct{}

// Redraw will re-draw what's inside the PTY window. In the case of a local
// PTY, setting the size of it will accomplish this.
func (p NativePTY) Redraw(w *term.Winsize) error {
	err := term.SetWinsize(0, w)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// GetSize gets the current physical size of the terminal window.
func (p NativePTY) GetSize() (*term.Winsize, error) {
	w, err := term.GetWinsize(0)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return w, nil
}

// SetSize sets the current physical size of the terminal window.
func (p NativePTY) SetSize(w *term.Winsize) {
	// Note that \x1b == \e.
	os.Stdout.Write([]byte(fmt.Sprintf("\x1b[8;%d;%dt", w.Height, w.Width)))
}

// WebPTY represents a web based terminal emulators like term.js.
type WebPTY struct {
	ID      string
	Conn    *websocket.Conn
	WinSize *term.Winsize
}

// Redraw will re-draw what's inside the PTY window.
func (p WebPTY) Redraw(w *term.Winsize) error {
	fmt.Printf("--> WebPTY: Redraw: %v\n", w)

	event := events.EventFields{
		"event": "resize",
		"sid":   p.ID,
		"size":  fmt.Sprint("%d:%d", w.Width, w.Height),
		"time":  time.Now().String(),
	}

	err := websocket.JSON.Send(p.Conn, event)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// GetSize gets the current physical size of the terminal window.
func (p WebPTY) GetSize() (*term.Winsize, error) {
	return p.WinSize, nil
}

// SetSize sets the current physical size of the terminal window. In the case
// of the web PTY, the size of the browser window can not be updated from
// Javascript so this function.
func (p WebPTY) SetSize(winSize *term.Winsize) {
	p.WinSize = winSize
}
