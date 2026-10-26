// tap is a transparent capture proxy: game clients connect to it instead of
// the real server, every packet is relayed upstream and decoded into a JSONL
// capture for disassembly. -advertise points SC_10801's gateway/proxy fields
// back at the tap and -game-server does the same for the server lists of
// SC_10019/SC_10021; without them packets are relayed verbatim.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ggmolly/belfast/internal/tap"
)

func main() {
	listen := flag.String("listen", ":80", "listen address")
	upstream := flag.String("upstream", "", "upstream host:port to relay to (required)")
	capture := flag.String("capture", "capture.jsonl", "JSONL capture output path")
	advertise := flag.String("advertise", "", "host[:port] to rewrite SC_10801's gateway/proxy to (default: leave SC_10801 untouched; a bare host keeps the dialed port)")
	gameServer := flag.String("game-server", "", "host[:port] to rewrite SC_10019/SC_10021's server list to (default: leave them untouched; a bare host keeps each server's port)")
	flag.Parse()
	if *upstream == "" {
		fmt.Fprintln(os.Stderr, "tap: -upstream is required")
		os.Exit(1)
	}
	file, err := os.OpenFile(*capture, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tap: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()
	if err := (&tap.Tap{
		Listen: *listen, Upstream: *upstream, Sink: tap.NewSink(file),
		Advertise: *advertise, GameServer: *gameServer,
	}).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "tap: %v\n", err)
		os.Exit(1)
	}
}
