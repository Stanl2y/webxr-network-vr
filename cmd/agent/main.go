// Command agent captures (or synthesises) packet records, samples them and
// streams 20 Hz MessagePack frames to WebSocket viewers.
//
//	agent --synth --pps 60000 --addr :8080 --web web/dist
//	agent --pcap trace.pcap                  (build with -tags pcap)
//	sudo agent --xdp-iface eth0 --xdp-obj bpf/xdp.o   (Linux only)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/Stanl2y/webxr-network-vr/internal/capture/synth"
	"github.com/Stanl2y/webxr-network-vr/internal/capture/xdp"
	"github.com/Stanl2y/webxr-network-vr/internal/frame"
	"github.com/Stanl2y/webxr-network-vr/internal/record"
	"github.com/Stanl2y/webxr-network-vr/internal/sampler"
	"github.com/Stanl2y/webxr-network-vr/internal/server"
)

// pcapReplay is set by pcap_enabled.go when built with -tags pcap.
var pcapReplay func(ctx context.Context, path string, realtime bool, emit func(record.Record)) (int, error)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		useSynth = flag.Bool("synth", false, "generate synthetic traffic (works on any OS)")
		pps      = flag.Int("pps", 10_000, "synthetic offered load in packets/s")
		seed     = flag.Int64("seed", 1, "synthetic generator seed")
		addr     = flag.String("addr", ":8080", "HTTP/WebSocket listen address")
		webDir   = flag.String("web", "", "serve this directory at / (e.g. web/dist)")
		pcapPath = flag.String("pcap", "", "replay a .pcap file (requires -tags pcap)")
		xdpIface = flag.String("xdp-iface", "", "attach XDP to this interface (Linux)")
		xdpObj   = flag.String("xdp-obj", "bpf/xdp.o", "compiled XDP object")
		duration = flag.Duration("duration", 0, "exit after this long (0 = run until Ctrl-C)")
		quiet    = flag.Bool("quiet", false, "suppress per-second stats")
	)
	flag.Parse()

	sources := 0
	for _, on := range []bool{*useSynth, *pcapPath != "", *xdpIface != ""} {
		if on {
			sources++
		}
	}
	if sources != 1 {
		return errors.New("choose exactly one source: --synth, --pcap FILE or --xdp-iface IFACE")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	hub := server.NewHub()
	hub.Log = log
	batcher := frame.NewBatcher(sampler.New(sampler.Defaults()), frame.DefaultInterval)

	srv := &http.Server{Addr: *addr, Handler: server.Mux(hub, *webDir), ReadHeaderTimeout: 5 * time.Second}
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.ListenAndServe() }()
	log.Info("listening", "addr", *addr, "ws", "/ws", "web", *webDir)

	srcErr := make(chan error, 1)
	switch {
	case *useSynth:
		log.Info("source", "kind", "synth", "pps", *pps)
		g := synth.New(synth.Config{PPS: *pps, Seed: *seed})
		go func() { g.Run(ctx, batcher.Add); srcErr <- nil }()
	case *pcapPath != "":
		if pcapReplay == nil {
			return errors.New("this binary was built without pcap support; rebuild with -tags pcap")
		}
		log.Info("source", "kind", "pcap", "file", *pcapPath)
		go func() {
			n, err := pcapReplay(ctx, *pcapPath, true, batcher.Add)
			log.Info("pcap replay finished", "records", n)
			srcErr <- err
		}()
	default:
		if !xdp.Supported {
			return xdp.Run(ctx, "", "", 0, nil)
		}
		log.Info("source", "kind", "xdp", "iface", *xdpIface, "obj", *xdpObj)
		go func() { srcErr <- xdp.Run(ctx, *xdpObj, *xdpIface, 0, batcher.Add) }()
	}

	done := make(chan struct{})
	var acc statsAcc
	go batcher.Run(done, func(f frame.Frame, st sampler.Stats) {
		hub.Broadcast(f)
		if line, ok := acc.add(st, f); ok && !*quiet {
			log.Info("stats", append(line, "clients", hub.Clients())...)
		}
	})

	var err error
	select {
	case <-ctx.Done():
	case err = <-srcErr:
	case err = <-srvErr:
	}
	close(done)
	shCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shCtx)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// statsAcc sums per-tick stats into one log line per second (20 ticks).
type statsAcc struct {
	ticks                                    int
	arrived, emitted, sampled, throttled     uint64
	drops, weight, aggTicks, droppedTicksSum uint64
	k                                        uint32
	flows                                    int
}

func (a *statsAcc) add(st sampler.Stats, f frame.Frame) ([]any, bool) {
	a.ticks++
	a.arrived += st.Arrived
	a.emitted += st.Emitted
	a.sampled += st.SampledOut
	a.throttled += st.Throttled
	a.drops += st.Drops
	a.droppedTicksSum += uint64(f.DroppedTicks)
	if st.DropsAggregated {
		a.aggTicks++
	}
	if st.K > a.k {
		a.k = st.K
	}
	a.flows = st.Flows
	recs, _ := record.DecodeAll(f.Records)
	for _, r := range recs {
		a.weight += uint64(r.Weight)
	}
	if a.ticks < 20 {
		return nil, false
	}
	line := []any{
		"pps_in", a.arrived, "k", a.k, "records_out", a.emitted,
		"sampled_out", a.sampled, "hh_throttled", a.throttled,
		"drops", a.drops, "drop_agg_ticks", a.aggTicks,
		"weight_sum", a.weight, "flows", a.flows, "late_ticks", a.droppedTicksSum,
	}
	*a = statsAcc{}
	return line, true
}
