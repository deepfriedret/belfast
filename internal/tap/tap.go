// Package tap is a transparent framing-aware proxy for the game protocol:
// every client connection is relayed verbatim to a fixed upstream while each
// framed packet is decoded into a JSONL capture for later disassembly.
// Non-protocol traffic on the same port (HTTP probes) is relayed too and
// captured raw.
//
// SC_10801 and the server lists of SC_10019/SC_10021 can be pointed back at
// the tap, so the client doesn't leave the capture for the official gateway or
// game servers. That is opt-in: without Advertise or GameServer every packet
// is relayed verbatim.
package tap

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	"github.com/ggmolly/belfast/internal/logger"
	"github.com/ggmolly/belfast/internal/protobuf"
	"github.com/ggmolly/belfast/internal/protocol"
)

// The replies that name an address the client connects to next.
const (
	scServerList   = 10019 // SC_10019, the server list
	scLogin        = 10021 // SC_10021, the login result with the server list
	scVersionCheck = 10801 // SC_10801, the version check reply (gateway address)
)

// Sink writes capture lines as JSONL; safe for concurrent use.
type Sink struct {
	mu sync.Mutex
	w  io.Writer
}

func NewSink(w io.Writer) *Sink { return &Sink{w: w} }

func (s *Sink) line(fields map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(fields)
	if err != nil {
		return
	}
	fmt.Fprintf(s.w, "%s\n", data)
}

// Tap relays connections from Listen to Upstream, capturing every frame.
type Tap struct {
	Listen   string
	Upstream string
	Sink     *Sink
	// Advertise is the gateway host[:port] SC_10801 points the client at.
	// Empty leaves SC_10801 untouched. A bare host keeps the port the client
	// dialed.
	Advertise string
	// GameServer is the host[:port] the server list (SC_10019, SC_10021)
	// points the client at. Empty leaves the server lists untouched. A bare
	// host keeps each server's port: a tap listening on the game server's port
	// can then relay it. A host:port sends every entry to that one endpoint
	// instead.
	GameServer string
}

func (t *Tap) Run() error {
	listener, err := net.Listen("tcp", t.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	logger.LogEvent("Tap", "Run", fmt.Sprintf("listening on %s -> %s", t.Listen, t.Upstream), logger.LOG_LEVEL_INFO)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go t.handle(conn)
	}
}

func (t *Tap) handle(client net.Conn) {
	upstream, err := net.Dial("tcp", t.Upstream)
	if err != nil {
		logger.LogEvent("Tap", "Dial", fmt.Sprintf("upstream %s: %v", t.Upstream, err), logger.LOG_LEVEL_ERROR)
		client.Close()
		return
	}
	s := &session{tap: t, client: client, upstream: upstream}
	if t.Advertise != "" {
		gateway := resolveTarget(client, t.Advertise)
		s.advertiseHost, s.advertisePort = gateway.host, gateway.port
	}
	if t.GameServer != "" {
		game := resolveTarget(client, t.GameServer)
		s.gameHost, s.gamePort, s.gamePortSet = game.host, game.port, game.portSet
	}
	t.Sink.line(map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339Nano), "event": "open",
		"client": client.RemoteAddr().String(), "upstream": t.Upstream,
	})
	done := make(chan struct{}, 2)
	go s.pump(s.upstream, s.client, "CS", done)
	go s.pump(s.client, s.upstream, "SC", done)
	<-done
	s.close()
	<-done
	t.Sink.line(map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339Nano), "event": "close",
		"client": client.RemoteAddr().String(),
	})
}

type session struct {
	tap       *Tap
	client    net.Conn
	upstream  net.Conn
	closeOnce sync.Once
	// advertiseHost and advertisePort are where SC_10801 points the client,
	// see Tap.Advertise.
	advertiseHost string
	advertisePort uint32
	// gameHost, gamePort and gamePortSet are where SC_10019/SC_10021 point
	// the client, see Tap.GameServer.
	gameHost    string
	gamePort    uint32
	gamePortSet bool
}

// target is an address a rewrite points the client at. portSet is false when
// the source named no port: SC_10801 then keeps the tap's port, the server
// list keeps each server's.
type target struct {
	host    string
	port    uint32
	portSet bool
}

// dialedTarget is the address the client dialed, from the accepted socket.
func dialedTarget(client net.Conn) target {
	host, portText, err := net.SplitHostPort(client.LocalAddr().String())
	if err != nil {
		return target{}
	}
	port, err := strconv.ParseUint(portText, 10, 32)
	if err != nil {
		return target{host: host}
	}
	return target{host: host, port: uint32(port)}
}

// resolveTarget reads a host[:port], using the dialed address for the parts it
// leaves out.
func resolveTarget(client net.Conn, address string) target {
	local := dialedTarget(client)
	if address == "" {
		return local
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		// a bare host
		return target{host: address, port: local.port}
	}
	port, err := strconv.ParseUint(portText, 10, 32)
	if err != nil {
		logger.LogEvent("Tap", "Address", fmt.Sprintf("invalid address %q: %v, not rewriting", address, err), logger.LOG_LEVEL_WARN)
		return target{}
	}
	if host == "" {
		host = local.host
	}
	return target{host: host, port: uint32(port), portSet: true}
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		s.client.Close()
		s.upstream.Close()
	})
}

// pump reads framed packets from src, captures them, and forwards them to dst
// (SC_10801, SC_10019 and SC_10021 are rewritten, see rewriteSC). Once a
// direction carries non-protocol traffic (e.g. the SDK's HTTP probe on the
// gateway port and its response), the rest of it is relayed raw and captured
// chunk by chunk.
func (s *session) pump(dst io.Writer, src io.Reader, dir string, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	prototype := protocol.ClientMessage
	if dir == "SC" {
		prototype = protocol.ServerMessage
	}
	var buf []byte
	chunk := make([]byte, 32<<10)
	for {
		n, err := src.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		for len(buf) > 0 {
			total, sizeErr := 0, error(nil)
			if len(buf) >= 2 {
				total, sizeErr = protocol.FrameSize(buf)
			}
			if len(buf) >= 3 && buf[2] != 0x00 || sizeErr != nil {
				s.relayRaw(dst, src, dir, buf, err == nil)
				s.close()
				return
			}
			if len(buf) < 2 || len(buf) < total {
				break
			}
			frame := buf[:total]
			buf = buf[total:]
			forward := frame
			if dir == "SC" {
				var event map[string]any
				forward, event = s.rewriteSC(frame)
				if event != nil {
					event["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
					event["dir"] = dir
					s.tap.Sink.line(event)
				}
			}
			s.capturePacket(dir, prototype, forward)
			if _, err := dst.Write(forward); err != nil {
				return
			}
		}
		if err != nil {
			s.close()
			return
		}
	}
}

// rewriteSC points the addresses of an SC_10801 or a server list at this tap.
// It returns the frame to forward and a capture event, nil when the frame is
// left alone.
func (s *session) rewriteSC(frame []byte) ([]byte, map[string]any) {
	switch protocol.ParseHeader(frame).ID {
	case scVersionCheck:
		return s.pointGateway(frame)
	case scServerList, scLogin:
		return s.pointServers(frame)
	}
	return frame, nil
}

// pointGateway rewrites an SC_10801's gateway and proxy fields to this tap, so
// the client reconnects here to log in instead of following the address the
// official gateway named. TW's reply names literal IPs (139.95.1.134:10080,
// proxy 128.1.32.232:10080): DNS can't change those, and the client leaves the
// capture. The rest of the reply (versions, CDN lists) is untouched.
func (s *session) pointGateway(frame []byte) ([]byte, map[string]any) {
	if s.advertiseHost == "" {
		return frame, nil
	}
	msg := &protobuf.SC_10801{}
	if err := proto.Unmarshal(frame[protocol.HeaderSize:], msg); err != nil {
		return frame, nil
	}
	upstreamGateway := address(msg.GetGatewayIp(), msg.GetGatewayPort())
	upstreamProxy := address(msg.GetProxyIp(), msg.GetProxyPort())
	msg.GatewayIp = proto.String(s.advertiseHost)
	msg.GatewayPort = proto.Uint32(s.advertisePort)
	msg.ProxyIp = proto.String(s.advertiseHost)
	msg.ProxyPort = proto.Uint32(s.advertisePort)
	payload, err := proto.Marshal(msg)
	if err != nil {
		return frame, nil
	}
	return framed(frame, payload), map[string]any{
		"event": "rewrite", "id": scVersionCheck, "kind": "gateway",
		"upstream_gateway": upstreamGateway, "upstream_proxy": upstreamProxy,
		"gateway": address(s.advertiseHost, s.advertisePort),
	}
}

// pointServers rewrites the server list of an SC_10019 or SC_10021 to
// GameServer, so the client connects to the capture for the game session too.
// The game servers name themselves by IP (TW: 139.95.1.134:10081-10085),
// which DNS can't change. Every entry gets GameServer's host and keeps its
// port unless GameServer named one. The rest of the reply (names, ids,
// ticket, notices) is untouched. Without GameServer the frame is left alone.
func (s *session) pointServers(frame []byte) ([]byte, map[string]any) {
	if s.gameHost == "" {
		return frame, nil
	}
	header := protocol.ParseHeader(frame)
	var message proto.Message
	var list []*protobuf.SERVERINFO
	switch header.ID {
	case scServerList:
		msg := &protobuf.SC_10019{}
		if err := proto.Unmarshal(frame[protocol.HeaderSize:], msg); err != nil {
			return frame, nil
		}
		message, list = msg, msg.Serverlist
	case scLogin:
		msg := &protobuf.SC_10021{}
		if err := proto.Unmarshal(frame[protocol.HeaderSize:], msg); err != nil {
			return frame, nil
		}
		message, list = msg, msg.Serverlist
	}
	if len(list) == 0 {
		return frame, nil
	}
	upstream := make([]string, 0, len(list))
	for _, server := range list {
		if server == nil {
			continue
		}
		upstream = append(upstream, address(server.GetIp(), server.GetPort()))
		server.Ip = proto.String(s.gameHost)
		if s.gamePortSet {
			server.Port = proto.Uint32(s.gamePort)
			server.ProxyIp = proto.String(s.gameHost)
			server.ProxyPort = proto.Uint32(s.gamePort)
			continue
		}
		// host only: keep the port, and point the fallback proxy at the tap
		// when the official entry had one (the last TW server doesn't)
		if server.GetProxyPort() != 0 {
			server.ProxyIp = proto.String(s.gameHost)
		} else if server.GetProxyIp() != "" {
			server.ProxyIp = proto.String("")
		}
	}
	payload, err := proto.Marshal(message)
	if err != nil {
		return frame, nil
	}
	endpoint := s.gameHost
	if s.gamePortSet {
		endpoint = address(s.gameHost, s.gamePort)
	}
	return framed(frame, payload), map[string]any{
		"event": "rewrite", "id": header.ID, "kind": "server-list",
		"server": endpoint, "port_preserved": !s.gamePortSet,
		"upstream_servers": upstream,
	}
}

// framed re-frames a payload with the original packet's id and index.
func framed(frame, payload []byte) []byte {
	header := protocol.ParseHeader(frame)
	return protocol.AppendFrame(nil, header.ID, header.Index, payload)
}

// address formats an address for a capture entry.
func address(host string, port uint32) string {
	return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
}

func (s *session) capturePacket(dir string, prototype func(int) proto.Message, frame []byte) {
	header := protocol.ParseHeader(frame)
	payload := frame[protocol.HeaderSize:]
	entry := map[string]any{
		"ts":  time.Now().UTC().Format(time.RFC3339Nano),
		"dir": dir, "id": header.ID, "len": len(payload),
	}
	if msg := prototype(header.ID); msg != nil {
		msg = msg.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(payload, msg); err == nil {
			entry["name"] = string(msg.ProtoReflect().Descriptor().Name())
			entry["text"] = prototext.Format(msg)
		} else {
			entry["hex"] = hex.EncodeToString(payload)
		}
	} else {
		entry["hex"] = hex.EncodeToString(payload)
	}
	s.tap.Sink.line(entry)
}

// relayRaw forwards non-protocol bytes verbatim: first pending, then (if more)
// everything else src sends until it closes, capturing each chunk.
func (s *session) relayRaw(dst io.Writer, src io.Reader, dir string, pending []byte, more bool) {
	s.captureRaw(dir, pending)
	if _, err := dst.Write(pending); err != nil || !more {
		return
	}
	chunk := make([]byte, 32<<10)
	for {
		n, err := src.Read(chunk)
		if n > 0 {
			s.captureRaw(dir, chunk[:n])
			if _, werr := dst.Write(chunk[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// captureRaw records a chunk of non-protocol traffic, as text when it is
// printable UTF-8 (HTTP), hex otherwise.
func (s *session) captureRaw(dir string, data []byte) {
	entry := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"event": "raw", "dir": dir, "len": len(data),
	}
	if utf8.Valid(data) && !bytes.ContainsFunc(data, func(r rune) bool {
		return unicode.IsControl(r) && r != '\r' && r != '\n' && r != '\t'
	}) {
		entry["text"] = string(data)
	} else {
		entry["hex"] = hex.EncodeToString(data)
	}
	s.tap.Sink.line(entry)
}
