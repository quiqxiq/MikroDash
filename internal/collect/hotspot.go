package collect

// Hotspot collector — management and monitoring of RouterOS captive portal.
//
//	/ip/hotspot/active            the active sessions (fast lane, every tick)
//	/ip/hotspot/host              connected hosts (fast lane)
//	/ip/hotspot/cookie            saved login cookies (fast lane)
//	/ip/hotspot/user              voucher accounts (slow lane, MINUS THE PASSWORD)
//	/ip/hotspot/user/profile      user profiles and rate limits (slow lane)
//	/ip/hotspot                   server instances (slow lane)
//	/ip/hotspot/profile           server profiles and login methods (slow lane)
//	/ip/hotspot/ip-binding        MAC/IP bypass rules (slow lane)
//	/ip/hotspot/walled-garden     domain allow rules (slow lane)
//	/ip/hotspot/walled-garden/ip  IP allow rules (slow lane)
//
// ── THE PASSWORD IS NEVER READ ───────────────────────────────────────────────
//
// As with PPP secrets, `/ip/hotspot/user` passwords are clear text on print.
// The collector's proplist omits `password`, so credentials never reach a browser
// payload. The write path uses `internal/resource`'s `TypeSecret` exclusively.

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"mikrodash/internal/routeros"
)

var (
	hotspotActiveCmd = routeros.Cmd{Path: "/ip/hotspot/active/print", Args: []string{
		"=.proplist=.id,server,user,domain,address,mac-address,login-by,uptime,keepalive-timeout,time-left,idle-time,bytes-in,bytes-out,packets-in,packets-out",
	}}
	hotspotHostCmd = routeros.Cmd{Path: "/ip/hotspot/host/print", Args: []string{
		"=.proplist=.id,mac-address,address,to-address,server,bridge-port,uptime,idle-time,bytes-in,bytes-out,authorized,bypassed,comment",
	}}
	hotspotCookieCmd = routeros.Cmd{Path: "/ip/hotspot/cookie/print", Args: []string{
		"=.proplist=.id,user,mac-address,domain,expires-in",
	}}

	hotspotUserCmd = routeros.Cmd{Path: "/ip/hotspot/user/print", Args: []string{
		"=.proplist=.id,name,profile,server,limit-uptime,limit-bytes-in,limit-bytes-out,limit-bytes-total,routes,email,comment,disabled",
	}}
	hotspotUserProfileCmd = routeros.Cmd{Path: "/ip/hotspot/user/profile/print", Args: []string{
		"=.proplist=.id,name,shared-users,rate-limit,idle-timeout,keepalive-timeout,status-autorefresh,address-pool,transparent-proxy,open-status-page,mac-cookie-timeout",
	}}
	hotspotServerCmd = routeros.Cmd{Path: "/ip/hotspot/print", Args: []string{
		"=.proplist=.id,name,interface,address-pool,profile,idle-timeout,keepalive-timeout,addresses-per-mac,disabled",
	}}
	hotspotServerProfileCmd = routeros.Cmd{Path: "/ip/hotspot/profile/print", Args: []string{
		"=.proplist=.id,name,hotspot-address,dns-name,html-directory,rate-limit,http-proxy,smtp-server,login-by,ssl-certificate",
	}}
	hotspotIPBindingCmd = routeros.Cmd{Path: "/ip/hotspot/ip-binding/print", Args: []string{
		"=.proplist=.id,mac-address,address,to-address,server,type,comment,disabled",
	}}
	hotspotWalledGardenCmd = routeros.Cmd{Path: "/ip/hotspot/walled-garden/print", Args: []string{
		"=.proplist=.id,dst-host,dst-port,path,action,server,comment,disabled",
	}}
	hotspotWalledGardenIPCmd = routeros.Cmd{Path: "/ip/hotspot/walled-garden/ip/print", Args: []string{
		"=.proplist=.id,dst-address,protocol,dst-port,action,server,comment,disabled",
	}}
)

const hotspotConfigEvery = 12
const hotspotHeartbeat = 15 * time.Second
const hotspotIdleAfterSec = 10.0

type HotspotActiveSession struct {
	ID               string   `json:"id"`
	Server           string   `json:"server"`
	User             string   `json:"user"`
	Domain           string   `json:"domain"`
	Address          string   `json:"address"`
	MACAddress       string   `json:"macAddress"`
	LoginBy          string   `json:"loginBy"`
	Uptime           string   `json:"uptime"`
	KeepaliveTimeout string   `json:"keepaliveTimeout"`
	TimeLeft         string   `json:"timeLeft"`
	IdleTime         string   `json:"idleTime"`
	BytesIn          int      `json:"bytesIn"`
	BytesOut         int      `json:"bytesOut"`
	PacketsIn        int      `json:"packetsIn"`
	PacketsOut       int      `json:"packetsOut"`
	RXRate           *float64 `json:"rxRate"`
	TXRate           *float64 `json:"txRate"`
}

type HotspotUser struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Profile         string `json:"profile"`
	Server          string `json:"server"`
	LimitUptime     string `json:"limitUptime"`
	LimitBytesIn    *int   `json:"limitBytesIn"`
	LimitBytesOut   *int   `json:"limitBytesOut"`
	LimitBytesTotal *int   `json:"limitBytesTotal"`
	Routes          string `json:"routes"`
	Email           string `json:"email"`
	Comment         string `json:"comment"`
	Disabled        bool   `json:"disabled"`
	Connected       bool   `json:"connected"`
	ActiveIP        string `json:"activeIp"`
	ActiveMAC       string `json:"activeMac"`
	ActiveUptime    string `json:"activeUptime"`
}

type HotspotUserProfile struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	SharedUsers       string `json:"sharedUsers"`
	RateLimit         string `json:"rateLimit"`
	IdleTimeout       string `json:"idleTimeout"`
	KeepaliveTimeout  string `json:"keepaliveTimeout"`
	StatusAutorefresh string `json:"statusAutorefresh"`
	AddressPool       string `json:"addressPool"`
	TransparentProxy  bool   `json:"transparentProxy"`
	OpenStatusPage    string `json:"openStatusPage"`
	MACCookieTimeout  string `json:"macCookieTimeout"`
}

type HotspotServer struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Interface        string `json:"interface"`
	AddressPool      string `json:"addressPool"`
	Profile          string `json:"profile"`
	IdleTimeout      string `json:"idleTimeout"`
	KeepaliveTimeout string `json:"keepaliveTimeout"`
	AddressesPerMAC  string `json:"addressesPerMac"`
	Disabled         bool   `json:"disabled"`
}

type HotspotServerProfile struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	HotspotAddress string `json:"hotspotAddress"`
	DNSName        string `json:"dnsName"`
	HTMLDirectory  string `json:"htmlDirectory"`
	RateLimit      string `json:"rateLimit"`
	HTTPProxy      string `json:"httpProxy"`
	SMTPServer     string `json:"smtpServer"`
	LoginBy        string `json:"loginBy"`
	SSLCertificate string `json:"sslCertificate"`
}

type HotspotHost struct {
	ID         string `json:"id"`
	MACAddress string `json:"macAddress"`
	Address    string `json:"address"`
	ToAddress  string `json:"toAddress"`
	Server     string `json:"server"`
	BridgePort string `json:"bridgePort"`
	Uptime     string `json:"uptime"`
	IdleTime   string `json:"idleTime"`
	BytesIn    int    `json:"bytesIn"`
	BytesOut   int    `json:"bytesOut"`
	Authorized bool   `json:"authorized"`
	Bypassed   bool   `json:"bypassed"`
	Comment    string `json:"comment"`
}

type HotspotIPBinding struct {
	ID         string `json:"id"`
	MACAddress string `json:"macAddress"`
	Address    string `json:"address"`
	ToAddress  string `json:"toAddress"`
	Server     string `json:"server"`
	Type       string `json:"type"`
	Comment    string `json:"comment"`
	Disabled   bool   `json:"disabled"`
}

type HotspotWalledGarden struct {
	ID       string `json:"id"`
	DstHost  string `json:"dstHost"`
	DstPort  string `json:"dstPort"`
	Path     string `json:"path"`
	Action   string `json:"action"`
	Server   string `json:"server"`
	Comment  string `json:"comment"`
	Disabled bool   `json:"disabled"`
}

type HotspotWalledGardenIP struct {
	ID         string `json:"id"`
	DstAddress string `json:"dstAddress"`
	Protocol   string `json:"protocol"`
	DstPort    string `json:"dstPort"`
	Action     string `json:"action"`
	Server     string `json:"server"`
	Comment    string `json:"comment"`
	Disabled   bool   `json:"disabled"`
}

type HotspotCookie struct {
	ID         string `json:"id"`
	User       string `json:"user"`
	MACAddress string `json:"macAddress"`
	Domain     string `json:"domain"`
	ExpiresIn  string `json:"expiresIn"`
}

type HotspotPayload struct {
	TS             int64                   `json:"ts"`
	PollMs         int                     `json:"pollMs"`
	Active         []HotspotActiveSession  `json:"active"`
	Users          []HotspotUser           `json:"users"`
	UserProfiles   []HotspotUserProfile    `json:"userProfiles"`
	Servers        []HotspotServer         `json:"servers"`
	ServerProfiles []HotspotServerProfile  `json:"serverProfiles"`
	Hosts          []HotspotHost           `json:"hosts"`
	IPBindings     []HotspotIPBinding      `json:"ipBindings"`
	WalledGarden   []HotspotWalledGarden   `json:"walledGarden"`
	WalledGardenIP []HotspotWalledGardenIP `json:"walledGardenIp"`
	Cookies        []HotspotCookie         `json:"cookies"`
	TotalRXRate    *float64                `json:"totalRxRate"`
	TotalTXRate    *float64                `json:"totalTxRate"`
	Available      bool                    `json:"available"`
}

type hotspotSample struct {
	rx, tx int
	ts     time.Time
}

type Hotspot struct {
	tableCore[HotspotPayload]
	emit Emit

	prev           map[string]hotspotSample
	users          []HotspotUser
	userProfiles   []HotspotUserProfile
	servers        []HotspotServer
	serverProfiles []HotspotServerProfile
	hosts          []HotspotHost
	ipBindings     []HotspotIPBinding
	walledGarden   []HotspotWalledGarden
	walledGardenIP []HotspotWalledGardenIP
	cookies        []HotspotCookie
	lastActiveRows []routeros.Reply

	activeAvail         *bool
	userAvail           *bool
	userProfileAvail    *bool
	serverAvail         *bool
	serverProfileAvail  *bool
	hostAvail           *bool
	ipBindingAvail      *bool
	walledGardenAvail   *bool
	walledGardenIPAvail *bool
	cookieAvail         *bool
}

func NewHotspot(ros Reader, emit Emit, pollMs int) *Hotspot {
	h := &Hotspot{emit: emit, prev: map[string]hotspotSample{}}
	h.setup(h, ros, pollMs, tableSpec{
		cmd: hotspotActiveCmd, poll: [3]int{1000, 1000, 60000},
		also:      []routeros.Cmd{hotspotUserCmd},
		slowEvery: hotspotConfigEvery, heartbeat: hotspotHeartbeat,
	})
	return h
}

func (h *Hotspot) read(cmd routeros.Cmd, flag **bool) []routeros.Reply {
	rows, _ := readOptional(h.readShared, cmd, flag)
	return rows
}

func ParseHotspotActive(rows []routeros.Reply, prev map[string]hotspotSample, now time.Time) ([]HotspotActiveSession, map[string]hotspotSample) {
	out := make([]HotspotActiveSession, 0, len(rows))
	next := make(map[string]hotspotSample, len(rows))

	for _, r := range rows {
		if r["user"] == "" && r["address"] == "" {
			continue
		}
		rx := pppInt(r["bytes-in"])
		tx := pppInt(r["bytes-out"])
		key := r[".id"]
		if key == "" {
			key = r["user"] + "/" + r["address"]
		}
		var rxRate, txRate *float64
		pr, seen := prev[key]
		if seen && now.After(pr.ts) {
			dtSec := now.Sub(pr.ts).Seconds()
			rr := max(0, float64(rx-pr.rx)/dtSec)
			tr := max(0, float64(tx-pr.tx)/dtSec)
			if rx == pr.rx && tx == pr.tx && dtSec > hotspotIdleAfterSec {
				rr, tr = 0, 0
			}
			rxRate, txRate = &rr, &tr
		}
		if !seen || rx != pr.rx || tx != pr.tx {
			next[key] = hotspotSample{rx: rx, tx: tx, ts: now}
		} else {
			next[key] = pr
		}

		out = append(out, HotspotActiveSession{
			ID:               r[".id"],
			Server:           r["server"],
			User:             r["user"],
			Domain:           r["domain"],
			Address:          r["address"],
			MACAddress:       r["mac-address"],
			LoginBy:          r["login-by"],
			Uptime:           r["uptime"],
			KeepaliveTimeout: r["keepalive-timeout"],
			TimeLeft:         r["time-left"],
			IdleTime:         r["idle-time"],
			BytesIn:          rx,
			BytesOut:         tx,
			PacketsIn:        pppInt(r["packets-in"]),
			PacketsOut:       pppInt(r["packets-out"]),
			RXRate:           rxRate,
			TXRate:           txRate,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return Collate(out[i].User, out[j].User) < 0 })
	return out, next
}

func (h *Hotspot) loadFastLane() {
	hosts := make([]HotspotHost, 0)
	for _, r := range h.read(hotspotHostCmd, &h.hostAvail) {
		if r["mac-address"] == "" && r["address"] == "" {
			continue
		}
		hosts = append(hosts, HotspotHost{
			ID:         r[".id"],
			MACAddress: r["mac-address"],
			Address:    r["address"],
			ToAddress:  r["to-address"],
			Server:     r["server"],
			BridgePort: r["bridge-port"],
			Uptime:     r["uptime"],
			IdleTime:   r["idle-time"],
			BytesIn:    pppInt(r["bytes-in"]),
			BytesOut:   pppInt(r["bytes-out"]),
			Authorized: boolOf(r["authorized"]),
			Bypassed:   boolOf(r["bypassed"]),
			Comment:    r["comment"],
		})
	}
	cookies := make([]HotspotCookie, 0)
	for _, r := range h.read(hotspotCookieCmd, &h.cookieAvail) {
		if r["user"] == "" && r["mac-address"] == "" {
			continue
		}
		cookies = append(cookies, HotspotCookie{
			ID:         r[".id"],
			User:       r["user"],
			MACAddress: r["mac-address"],
			Domain:     r["domain"],
			ExpiresIn:  r["expires-in"],
		})
	}
	h.hosts, h.cookies = hosts, cookies
}

func (h *Hotspot) parseUsers(rows []routeros.Reply) []HotspotUser {
	users := make([]HotspotUser, 0, len(rows))
	for _, r := range rows {
		if r["name"] == "" {
			continue
		}
		users = append(users, HotspotUser{
			ID:              r[".id"],
			Name:            r["name"],
			Profile:         r["profile"],
			Server:          r["server"],
			LimitUptime:     r["limit-uptime"],
			LimitBytesIn:    pppLimit(r["limit-bytes-in"]),
			LimitBytesOut:   pppLimit(r["limit-bytes-out"]),
			LimitBytesTotal: pppLimit(r["limit-bytes-total"]),
			Routes:          r["routes"],
			Email:           r["email"],
			Comment:         r["comment"],
			Disabled:        boolOf(r["disabled"]),
		})
	}
	sort.SliceStable(users, func(i, j int) bool { return Collate(users[i].Name, users[j].Name) < 0 })
	return users
}

// absorb receives streamed users from hotspotUserCmd.
func (h *Hotspot) absorb(_ int, rows []routeros.Reply, err error) (*HotspotPayload, string) {
	if err != nil && !menuGone(err) {
		return nil, ""
	}
	latchMenu(&h.userAvail, err)
	if err != nil {
		rows = nil
	}
	h.users = h.parseUsers(rows)
	return h.build(h.lastActiveRows)
}

func (h *Hotspot) loadConfig() {
	if len(h.users) == 0 {
		h.users = h.parseUsers(h.read(hotspotUserCmd, &h.userAvail))
	}

	userProfiles := make([]HotspotUserProfile, 0)
	for _, r := range h.read(hotspotUserProfileCmd, &h.userProfileAvail) {
		if r["name"] == "" {
			continue
		}
		userProfiles = append(userProfiles, HotspotUserProfile{
			ID:                r[".id"],
			Name:              r["name"],
			SharedUsers:       r["shared-users"],
			RateLimit:         r["rate-limit"],
			IdleTimeout:       r["idle-timeout"],
			KeepaliveTimeout:  r["keepalive-timeout"],
			StatusAutorefresh: r["status-autorefresh"],
			AddressPool:       r["address-pool"],
			TransparentProxy:  boolOf(r["transparent-proxy"]),
			OpenStatusPage:    r["open-status-page"],
			MACCookieTimeout:  r["mac-cookie-timeout"],
		})
	}

	servers := make([]HotspotServer, 0)
	for _, r := range h.read(hotspotServerCmd, &h.serverAvail) {
		if r["name"] == "" {
			continue
		}
		servers = append(servers, HotspotServer{
			ID:               r[".id"],
			Name:             r["name"],
			Interface:        r["interface"],
			AddressPool:      r["address-pool"],
			Profile:          r["profile"],
			IdleTimeout:      r["idle-timeout"],
			KeepaliveTimeout: r["keepalive-timeout"],
			AddressesPerMAC:  r["addresses-per-mac"],
			Disabled:         boolOf(r["disabled"]),
		})
	}

	serverProfiles := make([]HotspotServerProfile, 0)
	for _, r := range h.read(hotspotServerProfileCmd, &h.serverProfileAvail) {
		if r["name"] == "" {
			continue
		}
		serverProfiles = append(serverProfiles, HotspotServerProfile{
			ID:             r[".id"],
			Name:           r["name"],
			HotspotAddress: r["hotspot-address"],
			DNSName:        r["dns-name"],
			HTMLDirectory:  r["html-directory"],
			RateLimit:      r["rate-limit"],
			HTTPProxy:      r["http-proxy"],
			SMTPServer:     r["smtp-server"],
			LoginBy:        r["login-by"],
			SSLCertificate: r["ssl-certificate"],
		})
	}

	ipBindings := make([]HotspotIPBinding, 0)
	for _, r := range h.read(hotspotIPBindingCmd, &h.ipBindingAvail) {
		if r["mac-address"] == "" && r["address"] == "" {
			continue
		}
		ipBindings = append(ipBindings, HotspotIPBinding{
			ID:         r[".id"],
			MACAddress: r["mac-address"],
			Address:    r["address"],
			ToAddress:  r["to-address"],
			Server:     r["server"],
			Type:       r["type"],
			Comment:    r["comment"],
			Disabled:   boolOf(r["disabled"]),
		})
	}

	walledGarden := make([]HotspotWalledGarden, 0)
	for _, r := range h.read(hotspotWalledGardenCmd, &h.walledGardenAvail) {
		if r["dst-host"] == "" && r["path"] == "" {
			continue
		}
		walledGarden = append(walledGarden, HotspotWalledGarden{
			ID:       r[".id"],
			DstHost:  r["dst-host"],
			DstPort:  r["dst-port"],
			Path:     r["path"],
			Action:   r["action"],
			Server:   r["server"],
			Comment:  r["comment"],
			Disabled: boolOf(r["disabled"]),
		})
	}

	walledGardenIP := make([]HotspotWalledGardenIP, 0)
	for _, r := range h.read(hotspotWalledGardenIPCmd, &h.walledGardenIPAvail) {
		if r["dst-address"] == "" && r["dst-port"] == "" {
			continue
		}
		walledGardenIP = append(walledGardenIP, HotspotWalledGardenIP{
			ID:         r[".id"],
			DstAddress: r["dst-address"],
			Protocol:   r["protocol"],
			DstPort:    r["dst-port"],
			Action:     r["action"],
			Server:     r["server"],
			Comment:    r["comment"],
			Disabled:   boolOf(r["disabled"]),
		})
	}

	h.userProfiles = userProfiles
	h.servers = servers
	h.serverProfiles = serverProfiles
	h.ipBindings = ipBindings
	h.walledGarden = walledGarden
	h.walledGardenIP = walledGardenIP
}

func (h *Hotspot) derive(rows []routeros.Reply, err error, slow bool) (*HotspotPayload, string) {
	if err != nil && !menuGone(err) {
		return nil, ""
	}
	latchMenu(&h.activeAvail, err)
	if err != nil {
		h.retire()
		rows = nil
	}
	h.loadFastLane()
	if slow {
		h.loadConfig()
	}
	h.lastActiveRows = rows
	return h.build(rows)
}

func (h *Hotspot) send(pl HotspotPayload) { EvHotspotUpdate.Emit(h.emit, hotspotRooms.Join(), pl) }

func (h *Hotspot) reset() {
	clear(h.prev)
	h.activeAvail = nil
	h.userAvail = nil
	h.userProfileAvail = nil
	h.serverAvail = nil
	h.serverProfileAvail = nil
	h.hostAvail = nil
	h.ipBindingAvail = nil
	h.walledGardenAvail = nil
	h.walledGardenIPAvail = nil
	h.cookieAvail = nil
	h.lastActiveRows = nil
}

type HotspotInput struct {
	Rows           []routeros.Reply
	Prev           map[string]hotspotSample
	Users          []HotspotUser
	UserProfiles   []HotspotUserProfile
	Servers        []HotspotServer
	ServerProfiles []HotspotServerProfile
	Hosts          []HotspotHost
	IPBindings     []HotspotIPBinding
	WalledGarden   []HotspotWalledGarden
	WalledGardenIP []HotspotWalledGardenIP
	Cookies        []HotspotCookie
	Available      *bool
	PollMs         int
	Now            time.Time
}

func BuildHotspot(in HotspotInput) (*HotspotPayload, []HotspotActiveSession, map[string]hotspotSample) {
	active, nextPrev := ParseHotspotActive(in.Rows, in.Prev, in.Now)

	var totalRX, totalTX *float64
	known := 0
	var sumRX, sumTX float64
	for _, s := range active {
		if s.RXRate != nil {
			known++
			sumRX += *s.RXRate
			sumTX += *s.TXRate
		}
	}
	if known > 0 {
		totalRX, totalTX = &sumRX, &sumTX
	}

	activeByUser := make(map[string]HotspotActiveSession, len(active))
	for _, a := range active {
		activeByUser[a.User] = a
	}

	users := make([]HotspotUser, len(in.Users))
	for i, u := range in.Users {
		sess, online := activeByUser[u.Name]
		u.Connected = online
		if online {
			u.ActiveIP = sess.Address
			u.ActiveMAC = sess.MACAddress
			u.ActiveUptime = sess.Uptime
		}
		users[i] = u
	}

	userProfiles := in.UserProfiles
	if userProfiles == nil {
		userProfiles = []HotspotUserProfile{}
	}
	servers := in.Servers
	if servers == nil {
		servers = []HotspotServer{}
	}
	serverProfiles := in.ServerProfiles
	if serverProfiles == nil {
		serverProfiles = []HotspotServerProfile{}
	}
	hosts := in.Hosts
	if hosts == nil {
		hosts = []HotspotHost{}
	}
	ipBindings := in.IPBindings
	if ipBindings == nil {
		ipBindings = []HotspotIPBinding{}
	}
	walledGarden := in.WalledGarden
	if walledGarden == nil {
		walledGarden = []HotspotWalledGarden{}
	}
	walledGardenIP := in.WalledGardenIP
	if walledGardenIP == nil {
		walledGardenIP = []HotspotWalledGardenIP{}
	}
	cookies := in.Cookies
	if cookies == nil {
		cookies = []HotspotCookie{}
	}

	return &HotspotPayload{
		TS:             in.Now.UnixMilli(),
		PollMs:         in.PollMs,
		Active:         active,
		Users:          users,
		UserProfiles:   userProfiles,
		Servers:        servers,
		ServerProfiles: serverProfiles,
		Hosts:          hosts,
		IPBindings:     ipBindings,
		WalledGarden:   walledGarden,
		WalledGardenIP: walledGardenIP,
		Cookies:        cookies,
		TotalRXRate:    totalRX,
		TotalTXRate:    totalTX,
		Available:      MenuAvailable(in.Available),
	}, active, nextPrev
}

func (h *Hotspot) build(rows []routeros.Reply) (*HotspotPayload, string) {
	payload, active, nextPrev := BuildHotspot(HotspotInput{
		Rows:           rows,
		Prev:           h.prev,
		Users:          h.users,
		UserProfiles:   h.userProfiles,
		Servers:        h.servers,
		ServerProfiles: h.serverProfiles,
		Hosts:          h.hosts,
		IPBindings:     h.ipBindings,
		WalledGarden:   h.walledGarden,
		WalledGardenIP: h.walledGardenIP,
		Cookies:        h.cookies,
		Available:      h.activeAvail,
		PollMs:         h.pollMs.ms(),
		Now:            time.Now(),
	})
	h.prev = nextPrev

	var fp strings.Builder
	for _, a := range active {
		fp.WriteString(a.ID + "|" + a.User + "|" + a.Address + "|" + strconv.Itoa(a.BytesIn) + "|" + strconv.Itoa(a.BytesOut) + ";")
	}
	for _, u := range payload.Users {
		fp.WriteString(u.ID + "|" + u.Name + "|" + u.Profile + "|" + strconv.FormatBool(u.Disabled) + "|" + strconv.FormatBool(u.Connected) + ";")
	}
	for _, s := range payload.Servers {
		fp.WriteString(s.ID + "|" + s.Name + "|" + s.Interface + "|" + strconv.FormatBool(s.Disabled) + ";")
	}
	for _, hst := range payload.Hosts {
		fp.WriteString(hst.ID + "|" + hst.MACAddress + "|" + hst.Address + "|" + strconv.FormatBool(hst.Authorized) + ";")
	}
	for _, b := range payload.IPBindings {
		fp.WriteString(b.ID + "|" + b.MACAddress + "|" + b.Address + "|" + b.Type + "|" + strconv.FormatBool(b.Disabled) + ";")
	}
	fp.WriteString("|" + strconv.FormatBool(payload.Available))
	return payload, fp.String()
}
