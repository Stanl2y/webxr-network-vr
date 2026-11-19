package server

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Stanl2y/webxr-network-vr/internal/frame"
	"github.com/Stanl2y/webxr-network-vr/internal/record"
)

func newTestHub() (*Hub, chan struct{}) {
	h := NewHub()
	h.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	joined := make(chan struct{}, 4)
	h.OnConnect = func() { joined <- struct{}{} }
	return h, joined
}

func dial(t *testing.T, ctx context.Context, url string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(url, "http")+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitJoin(t *testing.T, joined chan struct{}) {
	t.Helper()
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("client never registered")
	}
}

func TestBroadcastReachesClient(t *testing.T) {
	h, joined := newTestHub()
	srv := httptest.NewServer(Mux(h, ""))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := dial(t, ctx, srv.URL)
	defer c.CloseNow()
	waitJoin(t, joined)

	want := frame.Build(frame.DefaultInterval, []record.Record{{TsNs: 42, FlowHash: 7, Weight: 3}})
	h.Broadcast(want)

	typ, b, err := c.Read(ctx)
	if err != nil || typ != websocket.MessageBinary {
		t.Fatalf("read: typ=%v err=%v", typ, err)
	}
	got, err := frame.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != 1 || got.BaseTsNs != 42 {
		t.Fatalf("got %+v", got)
	}
}

func TestSlowClientGetsDroppedTicks(t *testing.T) {
	h, _ := newTestHub()
	c := &client{ch: make(chan frame.Frame, clientBuffer)}
	h.clients[c] = struct{}{}
	for i := 0; i < clientBuffer+5; i++ {
		h.Broadcast(frame.Frame{TickMs: 50})
	}
	if len(c.ch) != clientBuffer || c.dropped.Load() != 5 {
		t.Fatalf("queued=%d dropped=%d, want %d and 5", len(c.ch), c.dropped.Load(), clientBuffer)
	}
}

func TestHealthz(t *testing.T) {
	h, _ := newTestHub()
	srv := httptest.NewServer(Mux(h, ""))
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", err, resp)
	}
	resp.Body.Close()
}
