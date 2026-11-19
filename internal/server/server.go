// Package server broadcasts encoded frames to WebSocket clients and
// optionally serves the built web viewer.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/Stanl2y/webxr-network-vr/internal/frame"
)

// clientBuffer is how many frames may queue per client before ticks are
// dropped for that client (and reported via dropped_ticks).
const clientBuffer = 8

type client struct {
	ch      chan frame.Frame
	dropped atomic.Uint32
}

// Hub fans frames out to every connected client.
type Hub struct {
	mu      sync.Mutex
	clients map[*client]struct{}
	// OnConnect, if set, is called after a client is registered.
	OnConnect func()
	Log       *slog.Logger
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{clients: make(map[*client]struct{}), Log: slog.Default()} }

// Clients returns the number of connected clients.
func (h *Hub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// Broadcast queues f for every client without blocking. A client whose
// buffer is full skips this tick and its dropped counter grows.
func (h *Hub) Broadcast(f frame.Frame) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c.ch <- f:
		default:
			c.dropped.Add(1)
		}
	}
}

// ServeHTTP upgrades to WebSocket and streams binary MessagePack frames.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx := conn.CloseRead(r.Context()) // we never read; this handles close frames

	c := &client{ch: make(chan frame.Frame, clientBuffer)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
	}()
	if h.OnConnect != nil {
		h.OnConnect()
	}
	h.Log.Info("viewer connected", "remote", r.RemoteAddr)

	for {
		select {
		case <-ctx.Done():
			h.Log.Info("viewer disconnected", "remote", r.RemoteAddr)
			return
		case f := <-c.ch:
			f.DroppedTicks += c.dropped.Swap(0)
			b, err := frame.Encode(f)
			if err != nil {
				h.Log.Error("encode frame", "err", err)
				return
			}
			wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = conn.Write(wctx, websocket.MessageBinary, b)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// Mux serves the hub at /ws and, when webDir is non-empty, static files at /.
func Mux(h *Hub, webDir string) *http.ServeMux {
	m := http.NewServeMux()
	m.Handle("/ws", h)
	m.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	if webDir != "" {
		m.Handle("/", http.FileServer(http.Dir(webDir)))
	}
	return m
}
