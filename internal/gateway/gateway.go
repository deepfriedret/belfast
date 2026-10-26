// Package gateway answers the packets the client sends to the gateway before
// it picks a game server: the version / asset hash check (CS_10800), the
// server list state check (CS_10018) and the account login (CS_10020), plus
// the SDK's HTTP reachability probe on the same port.
package gateway

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ggmolly/belfast/internal/connection"
	"github.com/ggmolly/belfast/internal/db"
	"github.com/ggmolly/belfast/internal/game"
	"github.com/ggmolly/belfast/internal/logger"
	"github.com/ggmolly/belfast/internal/packets"
	"github.com/ggmolly/belfast/internal/protobuf"
)

// Server is one entry of the server list.
type Server struct {
	ID   uint32
	Name string
	Host string
	Port uint32
}

// info is the server's SERVERINFO: state 0 is Server.STATUS's "Online"
// (model/vo/server.lua), tag_state 0 no badge. Servers with sort 0 are the
// candidates for the "Featured" slot, which is also the default server of a
// new device (ServerProxy:setServers). The proxy address is where the client
// retries when Host:Port can't be reached (ConnectionMgr:ConnectByProxy).
func (server Server) info() *protobuf.SERVERINFO {
	return &protobuf.SERVERINFO{
		Ids:       []uint32{server.ID},
		Ip:        proto.String(server.Host),
		Port:      proto.Uint32(server.Port),
		State:     proto.Uint32(0),
		Name:      proto.String(server.Name),
		TagState:  proto.Uint32(0),
		Sort:      proto.Uint32(0),
		ProxyIp:   proto.String(server.Host),
		ProxyPort: proto.Uint32(server.Port),
	}
}

// ProbeResponse answers the SDK's reachability probe (GET /?cmd=test?) as
// the official gateway does (captured).
var ProbeResponse = []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain;charset=utf-8\r\nContent-Length: 8\r\nConnection: keep-alive\r\n\r\nbad args")

// Official are the official release gateways per region, the default
// Upstream. EN is from the client's logcat (*all gate info), JP from
// yostarmgr.lua (isRelease). CN, KR and TW name theirs only in the native
// code: those are the gateways of nobbyfix/AzurLane-AssetDownloader
// (client_config.json) and wess09/AzurLaneServerStatus (checker.py), which
// agree on all five. Each answered a CS_10800 (2026-10-21) with its region's
// client version (CN 9.7.398, KR 8.5.79, TW 8.5.200). CN is bilibili's
// Android channel, whose version is the one AzurLaneLuaScripts dumps; its
// iOS channel is line1-login-ios-blhx.bilibiligame.net:80 (9.7.401 that
// day).
var Official = map[string]string{
	"EN": "blhxusgate.yo-star.com:80",
	"JP": "blhxjploginapi.azurlane.jp:80",
	"CN": "line1-login-bili-blhx.bilibiligame.net:80",
	"KR": "bl-kr-gate.xdg.com:80",
	"TW": "prod-all-login.azurlane.tw:10080",
}

// AssetCDN is each region's asset CDN: an Android client downloads the
// bundle list of its $azhash$ version from <cdn>/android/hash/<version> and
// the bundles from <cdn>/android/resource/<md5>. From
// nobbyfix/AzurLane-AssetDownloader's client_config.json, whose gateways are
// the ones in Official.
var AssetCDN = map[string]string{
	"EN": "https://blhxusstatic.yo-star.com",
	"JP": "https://blhxstatic.yo-star.com",
	"CN": "https://line3-patch-blhx.bilibiligame.net",
	"KR": "http://blcdn.imtxwy.com",
	"TW": "http://blhxstatic.azurlane.tw",
}

// versionTTL is how long an upstream SC_10801 is reused.
const versionTTL = 10 * time.Minute

// versionRetry is how long after a failed upstream fetch the upstream isn't
// asked again (the stale copy, or the error, is served meanwhile).
const versionRetry = 30 * time.Second

type Gateway struct {
	Servers []Server
	// Upstream is the official gateway (host:port). CS_10800 is relayed there
	// so the asset bundle hashes in SC_10801 always match the CDN the client
	// downloads from; the reply is passed through unchanged.
	Upstream string
	DB       *db.Store
	// TicketKey signs the server tickets, see LoadTicketKey.
	TicketKey []byte

	// the upstream SC_10801 cache, see version
	mu       sync.Mutex
	versions map[string]cachedVersion
	fetching map[string]*versionFetch
	failures map[string]versionFailure
	// androidState is the CS_10800.state the latest Android client sent,
	// see AssetHash
	androidState uint32
}

type cachedVersion struct {
	msg *protobuf.SC_10801
	at  time.Time
}

// versionFailure is the last failed upstream fetch of a key.
type versionFailure struct {
	err error
	at  time.Time
}

// versionFetch is an upstream request in flight, done is closed once msg or
// err is set.
type versionFetch struct {
	done chan struct{}
	msg  *protobuf.SC_10801
	err  error
}

// Register installs the gateway packet handlers.
func (gateway *Gateway) Register() {
	packets.Handle(gateway.handleVersionCheck)
	packets.Handle(gateway.handleServerState)
	packets.Handle(gateway.handleLogin)
	packets.Handle(gateway.handleServerLogin)
	packets.Handle(gateway.handleHeartbeat)
	packets.Handle(gateway.handleCreatePlayer)
	packets.Handle(gateway.handleRegister)
	packets.Handle(gateway.handleAccountSearch)
	packets.Handle(gateway.handleGatewaySwitch)
	packets.Handle(gateway.handleCheaterMark)
}

func (gateway *Gateway) serverList() []*protobuf.SERVERINFO {
	list := make([]*protobuf.SERVERINFO, len(gateway.Servers))
	for i, server := range gateway.Servers {
		list[i] = server.info()
	}
	return list
}

//belfast:static
func (gateway *Gateway) handleVersionCheck(client *connection.Client, req *protobuf.CS_10800) error {
	if req.GetPlatform() == androidPlatform {
		gateway.mu.Lock()
		gateway.androidState = req.GetState()
		gateway.mu.Unlock()
	}
	msg, err := gateway.version(req)
	if err != nil {
		return err
	}
	return client.Send(gateway.clientAddress(msg))
}

// clientAddress points the gateway and proxy fields of an upstream SC_10801
// at this server. Some regions' official gateways name their servers by IP
// (TW: 139.95.1.134:10080, proxy 128.1.32.232:10080) instead of a hostname:
// relayed unchanged, the client follows them to production and --server-host
// never applies. The rest of the reply (version, CDN lists) stays upstream.
func (gateway *Gateway) clientAddress(msg *protobuf.SC_10801) *protobuf.SC_10801 {
	if len(gateway.Servers) == 0 {
		return msg
	}
	server := gateway.Servers[0]
	msg = proto.Clone(msg).(*protobuf.SC_10801)
	msg.GatewayIp = proto.String(server.Host)
	msg.GatewayPort = proto.Uint32(server.Port)
	msg.ProxyIp = proto.String(server.Host)
	msg.ProxyPort = proto.Uint32(server.Port)
	return msg
}

//belfast:static
func (gateway *Gateway) handleServerState(client *connection.Client, req *protobuf.CS_10018) error {
	return client.Send(&protobuf.SC_10019{Serverlist: gateway.serverList()})
}

// handleLogin accepts any SDK login: arg2 is the SDK account uid, the account
// id is derived from it so it stays the same across logins and restarts. An
// inner login (login_type 2) must name an account registered with CS_10001.
func (gateway *Gateway) handleLogin(client *connection.Client, req *protobuf.CS_10020) error {
	account := accountID(req.GetArg2())
	if req.GetLoginType() == innerLoginType {
		var refused uint32
		var err error
		account, refused, err = gateway.innerAccount(req.GetArg1(), req.GetArg2())
		if err != nil {
			return err
		}
		if refused != 0 {
			logger.LogEvent("Gateway", "Login", fmt.Sprintf("inner login %q refused (%d) from %s", req.GetArg1(), refused, client.IP), logger.LOG_LEVEL_WARN)
			return client.Send(&protobuf.SC_10021{Result: proto.Uint32(refused)})
		}
	}
	ticket := gateway.issueTicket(account)
	notices, err := game.GatewayNotices(context.Background(), gateway.DB.Queries)
	if err != nil {
		return err
	}
	logger.LogEvent("Gateway", "Login", fmt.Sprintf("account %d (login type %d) from %s", account, req.GetLoginType(), client.IP), logger.LOG_LEVEL_INFO)
	return client.Send(&protobuf.SC_10021{
		Result:       proto.Uint32(0),
		Serverlist:   gateway.serverList(),
		AccountId:    proto.Uint32(account),
		ServerTicket: proto.String(ticket),
		NoticeList:   notices,
		Device:       proto.Uint32(req.GetDevice()),
	})
}

func accountID(uid string) uint32 {
	hash := fnv.New32a()
	hash.Write([]byte(uid))
	if id := hash.Sum32(); id != 0 {
		return id
	}
	return 1
}
