package tap

import (
	"bytes"
	"net"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/ggmolly/belfast/internal/protobuf"
	"github.com/ggmolly/belfast/internal/protocol"
)

// TestPointGateway: the TW gateway's literal IPs must become the tap's
// address, everything else in the reply (versions, CDN lists) must stay, and
// the received frame must be left intact for the capture.
func TestPointGateway(t *testing.T) {
	payload, err := proto.Marshal(&protobuf.SC_10801{
		GatewayIp:               proto.String("139.95.1.134"),
		GatewayPort:             proto.Uint32(10080),
		ProxyIp:                 proto.String("128.1.32.232"),
		ProxyPort:               proto.Uint32(10080),
		Url:                     proto.String("http://blhxstatic.azurlane.tw/android/"),
		Version:                 []string{"$azhash$abc"},
		IsTs:                    proto.Uint32(1),
		Timestamp:               proto.Uint32(1700000000),
		Monday_0OclockTimestamp: proto.Uint32(1699920000),
		CdnList:                 []string{"http://blhxstatic.azurlane.tw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := protocol.AppendFrame(nil, scVersionCheck, 7, payload)
	s := &session{advertiseHost: "192.168.1.50", advertisePort: 10080}

	forward, event := s.pointGateway(frame)
	if event == nil || event["upstream_gateway"] != "139.95.1.134:10080" || event["upstream_proxy"] != "128.1.32.232:10080" {
		t.Fatalf("capture event lost the upstream addresses: %v", event)
	}
	if !bytes.Equal(frame[protocol.HeaderSize:], payload) {
		t.Fatal("pointGateway mutated the received frame")
	}

	header := protocol.ParseHeader(forward)
	if header.ID != scVersionCheck || header.Index != 7 {
		t.Fatalf("header changed: %+v", header)
	}
	rewritten := &protobuf.SC_10801{}
	if err := proto.Unmarshal(forward[protocol.HeaderSize:], rewritten); err != nil {
		t.Fatal(err)
	}
	if rewritten.GetGatewayIp() != "192.168.1.50" || rewritten.GetGatewayPort() != 10080 {
		t.Fatalf("gateway = %s:%d", rewritten.GetGatewayIp(), rewritten.GetGatewayPort())
	}
	if rewritten.GetProxyIp() != "192.168.1.50" || rewritten.GetProxyPort() != 10080 {
		t.Fatalf("proxy = %s:%d", rewritten.GetProxyIp(), rewritten.GetProxyPort())
	}
	if len(rewritten.GetVersion()) != 1 || rewritten.GetVersion()[0] != "$azhash$abc" {
		t.Fatalf("versions changed: %v", rewritten.GetVersion())
	}
	if len(rewritten.GetCdnList()) != 1 || rewritten.GetCdnList()[0] != "http://blhxstatic.azurlane.tw" {
		t.Fatalf("CDN list changed: %v", rewritten.GetCdnList())
	}

	other := protocol.AppendFrame(nil, 10018, 0, payload)
	if got, event := s.rewriteSC(other); event != nil || !bytes.Equal(got, other) {
		t.Fatal("an unrelated frame was rewritten")
	}
}

// TestNoRewriteByDefault: without Advertise or GameServer every frame is
// relayed verbatim.
func TestNoRewriteByDefault(t *testing.T) {
	s := &session{}
	for _, id := range []int{scVersionCheck, scServerList, scLogin} {
		frame := protocol.AppendFrame(nil, id, 1, []byte{0})
		got, event := s.rewriteSC(frame)
		if event != nil || !bytes.Equal(got, frame) {
			t.Fatalf("id %d was rewritten without configuration", id)
		}
	}
}

// TestPointServerList: with a bare game host, SC_10019's literal IPs become
// the tap's host while each server keeps its port, and the last TW server's
// empty proxy stays empty.
func TestPointServerList(t *testing.T) {
	payload, err := proto.Marshal(&protobuf.SC_10019{Serverlist: []*protobuf.SERVERINFO{
		serverInfo(1, "139.95.1.134", 10081, "128.1.32.232", 10081),
		serverInfo(5, "139.95.1.134", 10085, "", 0),
	}})
	if err != nil {
		t.Fatal(err)
	}
	frame := protocol.AppendFrame(nil, scServerList, 3, payload)
	s := &session{gameHost: "192.168.1.50"}

	forward, event := s.pointServers(frame)
	preserved, _ := event["port_preserved"].(bool)
	if event == nil || !preserved || event["server"] != "192.168.1.50" {
		t.Fatalf("unexpected capture event: %v", event)
	}
	upstream, ok := event["upstream_servers"].([]string)
	if !ok || len(upstream) != 2 || upstream[0] != "139.95.1.134:10081" || upstream[1] != "139.95.1.134:10085" {
		t.Fatalf("upstream servers = %v", event["upstream_servers"])
	}
	if !bytes.Equal(frame[protocol.HeaderSize:], payload) {
		t.Fatal("pointServers mutated the received frame")
	}

	header := protocol.ParseHeader(forward)
	if header.ID != scServerList || header.Index != 3 {
		t.Fatalf("header changed: %+v", header)
	}
	rewritten := &protobuf.SC_10019{}
	if err := proto.Unmarshal(forward[protocol.HeaderSize:], rewritten); err != nil {
		t.Fatal(err)
	}
	if got := rewritten.GetServerlist()[0]; got.GetIp() != "192.168.1.50" || got.GetPort() != 10081 ||
		got.GetProxyIp() != "192.168.1.50" || got.GetProxyPort() != 10081 {
		t.Fatalf("first server = %v", got)
	}
	if got := rewritten.GetServerlist()[1]; got.GetIp() != "192.168.1.50" || got.GetPort() != 10085 ||
		got.GetProxyIp() != "" || got.GetProxyPort() != 0 {
		t.Fatalf("last server = %v", got)
	}
}

// TestPointLogin: SC_10021 keeps its result, account and ticket, and a named
// game server port forces every list entry to that endpoint.
func TestPointLogin(t *testing.T) {
	payload, err := proto.Marshal(&protobuf.SC_10021{
		Result:       proto.Uint32(0),
		Serverlist:   []*protobuf.SERVERINFO{serverInfo(1, "139.95.1.134", 10081, "128.1.32.232", 10081)},
		AccountId:    proto.Uint32(42),
		ServerTicket: proto.String("ticket"),
	})
	if err != nil {
		t.Fatal(err)
	}
	frame := protocol.AppendFrame(nil, scLogin, 4, payload)
	s := &session{gameHost: "192.168.1.50", gamePort: 10080, gamePortSet: true}

	forward, event := s.pointServers(frame)
	preserved, _ := event["port_preserved"].(bool)
	if event == nil || preserved || event["server"] != "192.168.1.50:10080" {
		t.Fatalf("unexpected capture event: %v", event)
	}
	rewritten := &protobuf.SC_10021{}
	if err := proto.Unmarshal(forward[protocol.HeaderSize:], rewritten); err != nil {
		t.Fatal(err)
	}
	got := rewritten.GetServerlist()[0]
	if got.GetIp() != "192.168.1.50" || got.GetPort() != 10080 ||
		got.GetProxyIp() != "192.168.1.50" || got.GetProxyPort() != 10080 {
		t.Fatalf("server = %v", got)
	}
	if rewritten.GetResult() != 0 || rewritten.GetAccountId() != 42 || rewritten.GetServerTicket() != "ticket" {
		t.Fatalf("login fields changed: %v", rewritten)
	}
}

func serverInfo(id uint32, ip string, port uint32, proxy string, proxyPort uint32) *protobuf.SERVERINFO {
	return &protobuf.SERVERINFO{
		Ids:       []uint32{id},
		Ip:        proto.String(ip),
		Port:      proto.Uint32(port),
		State:     proto.Uint32(0),
		Name:      proto.String("server"),
		ProxyIp:   proto.String(proxy),
		ProxyPort: proto.Uint32(proxyPort),
	}
}

// TestResolveTarget: empty Advertise uses the address the client dialed, a
// port overrides the port, and a bare host overrides only the host.
func TestResolveTarget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	dialed := server.LocalAddr().(*net.TCPAddr)

	for _, tc := range []struct {
		address string
		host    string
		port    uint32
		portSet bool
	}{
		{"", dialed.IP.String(), uint32(dialed.Port), false},
		{"10.0.0.2:20000", "10.0.0.2", 20000, true},
		{"10.0.0.2", "10.0.0.2", uint32(dialed.Port), false},
		{":20000", dialed.IP.String(), 20000, true},
	} {
		got := resolveTarget(server, tc.address)
		if got.host != tc.host || got.port != tc.port || got.portSet != tc.portSet {
			t.Errorf("resolveTarget(%q) = %+v, want %s:%d portSet=%v", tc.address, got, tc.host, tc.port, tc.portSet)
		}
	}
}
