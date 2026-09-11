// Package mockbmc 是深信服 BMC 的模拟服务端，用于在没有真实设备时联调与验收。
//
// 行为完全按 192.168.10.10.har 抓包还原，并且默认「严格模式」：
// 登录体、认证头、If-Match、PATCH 报文都按抓包校验，任何一项不符就返回真实风格的错误。
// 这样「在模拟端上跑通」才真正等价于「能对上真机」，而不是一个只回 200 的空壳。
//
// 同时提供故障注入开关（首次登录失败 / 首次 PATCH 返回 412 / 只接受单一认证头 等），
// 用来验证客户端各条容错分支是否真的生效。
package mockbmc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

/* --------------------------------- 配置 --------------------------------- */

// 认证头形式的取值。
const (
	AuthAny      = "any"          // 任意一种认证头都接受
	AuthXAuth    = "x-auth-token" // 只认 X-Auth-Token
	AuthXSRF     = "x-xsrf-token" // 只认 X-XSRF-TOKEN（抓包里的形式）
	AuthBearer   = "bearer"       // 只认 Authorization: Bearer
	DefaultToken = ""
)

// Options 是模拟端的可调参数。
type Options struct {
	Listen   string // HTTPS 监听地址，例如 127.0.0.1:8443
	HTTPDash string // 纯 HTTP 状态面板监听地址，留空则不启用

	User string
	Pass string

	IP   string // 初始管理口地址
	Mask string
	GW   string
	DHCP bool

	Latency time.Duration // 每个请求的人为延迟，模拟设备较慢

	// ---------- 真实性开关（默认全开，按抓包严格校验）----------

	// RequireLoginOem：登录体必须带 Oem.Public{EncryptFlag,LoginTag,SessionType}
	RequireLoginOem bool
	// RejectOemLogin：登录体只要带了 Oem 节点就拒绝。
	// 用来模拟不认识该参数的老固件，验证客户端会降级成简化登录体。
	// 与 RequireLoginOem 互斥，同时打开会导致任何登录体都被拒。
	RejectOemLogin bool
	// RequireIfMatch：PATCH 必须带正确的 If-Match
	RequireIfMatch bool
	// AuthMode：服务端认哪种认证头，取值见 AuthAny / AuthXAuth / AuthXSRF / AuthBearer
	AuthMode string
	// StrictOneAuthHeader：请求若带了不止一种认证头就拒绝。
	// 真实设备一般不这样，但用它可以让客户端「单一认证头」的降级分支真正被触发。
	StrictOneAuthHeader bool

	// ---------- 故障注入 ----------

	FailFirstLogin bool // 首次登录返回 400（触发客户端换登录体）
	FailFirstPatch bool // 首次 PATCH 返回 412（触发客户端重取 ETag 重试）
	DropAfterPatch bool // PATCH 成功后掐断连接（模拟设备立刻切走地址）

	Logf func(format string, args ...interface{})

	// Middleware 可选，用于在外层记录/观察每个请求
	Middleware func(http.Handler) http.Handler
}

func (o *Options) applyDefaults() {
	if o.Listen == "" {
		o.Listen = "127.0.0.1:8443"
	}
	if o.User == "" {
		o.User = "sangfor"
	}
	if o.Pass == "" {
		o.Pass = "S#AN$6fo81r"
	}
	if o.IP == "" {
		o.IP = "192.168.10.10"
	}
	if o.Mask == "" {
		o.Mask = "255.255.255.0"
	}
	if o.GW == "" {
		o.GW = "192.168.10.1"
	}
	if o.AuthMode == "" {
		o.AuthMode = AuthAny
	}
	if o.Logf == nil {
		o.Logf = func(string, ...interface{}) {}
	}
}

/* --------------------------------- 状态 --------------------------------- */

// ReqEntry 是面板上展示的一条请求记录。
type ReqEntry struct {
	At     string `json:"at"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Auth   string `json:"auth"`
	Note   string `json:"note"`
	Status int    `json:"status"`
}

// Server 是模拟出来的 BMC。
type Server struct {
	opts Options
	logf func(string, ...interface{})

	mu       sync.Mutex
	ip       string
	mask     string
	gw       string
	dhcp     bool
	etag     string
	token    string
	sessID   string
	loginCnt int
	patchCnt int
	dead     bool // DropAfterPatch 生效后，Redfish 接口不再响应
	history  []ReqEntry

	httpsSrv *http.Server
	dashSrv  *http.Server
	httpsLn  net.Listener
	dashLn   net.Listener

	onChange func(oldIP, newIP, mask, gw string) // 配置变更回调，供启动器打印醒目提示
}

// Start 启动模拟端。
func Start(opts Options) (*Server, error) {
	opts.applyDefaults()
	s := &Server{
		opts: opts,
		logf: opts.Logf,
		ip:   opts.IP,
		mask: opts.Mask,
		gw:   opts.GW,
		dhcp: opts.DHCP,
	}
	s.etag = quote(randStr(35))
	s.token = randStr(32)
	s.sessID = randStr(10)

	cert, err := selfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("生成自签证书失败：%w", err)
	}

	mux := s.routes()

	s.httpsLn, err = net.Listen("tcp", opts.Listen)
	if err != nil {
		return nil, fmt.Errorf("监听 %s 失败：%w", opts.Listen, err)
	}
	s.httpsSrv = &http.Server{
		Handler:           mux,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := s.httpsSrv.ServeTLS(s.httpsLn, "", ""); err != nil && err != http.ErrServerClosed {
			s.logf("HTTPS 服务退出：%v", err)
		}
	}()

	if opts.HTTPDash != "" {
		s.dashLn, err = net.Listen("tcp", opts.HTTPDash)
		if err != nil {
			// 面板只是辅助，端口被占用不该拖垮整个模拟端
			s.logf("⚠ 状态面板无法监听 %s（%v），已跳过；Redfish 接口不受影响", opts.HTTPDash, err)
			s.dashLn = nil
		} else {
			s.dashSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
			go func() {
				if err := s.dashSrv.Serve(s.dashLn); err != nil && err != http.ErrServerClosed {
					s.logf("面板服务退出：%v", err)
				}
			}()
		}
	}

	return s, nil
}

// URL 返回 HTTPS 基地址。
func (s *Server) URL() string { return "https://" + s.httpsLn.Addr().String() }

// Addr 返回实际监听地址（端口可能是系统分配的）。
func (s *Server) Addr() string { return s.httpsLn.Addr().String() }

// DashURL 返回面板地址，未启用时为空。
func (s *Server) DashURL() string {
	if s.dashLn == nil {
		return ""
	}
	return "http://" + s.dashLn.Addr().String()
}

// OnChange 注册配置变更回调（用于打印醒目提示）。
func (s *Server) OnChange(f func(oldIP, newIP, mask, gw string)) { s.onChange = f }

// Stop 关闭模拟端。
func (s *Server) Stop() {
	if s.httpsSrv != nil {
		_ = s.httpsSrv.Close()
	}
	if s.dashSrv != nil {
		_ = s.dashSrv.Close()
	}
}

// State 返回当前状态快照。
func (s *Server) State() (ip, mask, gw string, etag string, dhcp bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ip, s.mask, s.gw, s.etag, s.dhcp
}

/* -------------------------------- 路由 -------------------------------- */

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/redfish/v1/SessionService/Sessions", s.handleSessions)
	mux.HandleFunc("/redfish/v1/SessionService/Sessions/", s.handleSessions)
	mux.HandleFunc("/redfish/v1/Managers", s.handleManagers)
	mux.HandleFunc("/redfish/v1/Managers/1", s.handleManager)
	mux.HandleFunc("/redfish/v1/Managers/1/EthernetInterfaces", s.handleIfaces)
	mux.HandleFunc("/redfish/v1/Managers/1/EthernetInterfaces/eth0", s.handleEth0)
	mux.HandleFunc("/redfish/v1/Managers/1/EthernetInterfaces/Oem/Public/BondConfigure", s.handleBond)
	mux.HandleFunc("/redfish/v1/Managers/1/Oem/BmcConfigLock", s.handleConfigLock)
	mux.HandleFunc("/redfish/v1/Managers/1/NetworkProtocol", s.handleNetworkProtocol)
	mux.HandleFunc("/mock/state", s.handleMockState)
	mux.HandleFunc("/mock/reset", s.handleMockReset)

	if s.opts.Middleware != nil {
		return s.opts.Middleware(mux)
	}
	return mux
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	s.writeDashboard(w, r)
}

/* ------------------------------ 登录 / 登出 ------------------------------ */

type loginBody struct {
	UserName string `json:"UserName"`
	Password string `json:"Password"`
	Oem      *struct {
		Public struct {
			EncryptFlag bool   `json:"EncryptFlag"`
			LoginTag    int64  `json:"LoginTag"`
			SessionType string `json:"SessionType"`
		} `json:"Public"`
	} `json:"Oem"`
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleLogin(w, r)
	case http.MethodDelete:
		s.handleLogout(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.logf("  body: %s", strings.TrimSpace(string(raw)))

	if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		s.record(r, "Content-Type 不是 application/json", 415)
		writeErr(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	var lb loginBody
	if err := json.Unmarshal(raw, &lb); err != nil {
		s.record(r, "JSON 解析失败", 400)
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	s.mu.Lock()
	s.loginCnt++
	first := s.loginCnt == 1
	s.mu.Unlock()

	// 故障注入：首次登录直接拒绝，用来验证客户端的登录体降级
	if s.opts.FailFirstLogin && first {
		s.record(r, "故障注入：首次登录拒绝", 400)
		s.logf("  ⚑ 故障注入生效：首次登录返回 400")
		writeErr(w, http.StatusBadRequest, "invalid parameter: Oem")
		return
	}

	if lb.UserName != s.opts.User || lb.Password != s.opts.Pass {
		s.record(r, "账号或密码错误", 401)
		s.logf("  ✗ 账号或密码不匹配（服务端配置 %s）", s.opts.User)
		writeErr(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	// 模拟老固件：不认识 Oem 参数，带了就拒绝
	if s.opts.RejectOemLogin && lb.Oem != nil {
		s.record(r, "老固件模式：不接受 Oem 参数", 400)
		s.logf("  ✗ 本端配置为「不接受 Oem 参数」，客户端应降级为简化登录体")
		writeErr(w, http.StatusBadRequest, "unexpected parameter: Oem")
		return
	}

	// 严格模式：登录体必须与抓包一致
	if s.opts.RequireLoginOem {
		bad := ""
		if lb.Oem == nil {
			bad = "缺少 Oem.Public 节点"
		} else if lb.Oem.Public.SessionType != "WebUI" {
			bad = "Oem.Public.SessionType 必须是 WebUI"
		} else if lb.Oem.Public.LoginTag == 0 {
			bad = "Oem.Public.LoginTag 不能为 0"
		} else if lb.Oem.Public.EncryptFlag {
			bad = "Oem.Public.EncryptFlag 必须为 false"
		}
		if bad != "" {
			s.record(r, "登录体不符："+bad, 400)
			s.logf("  ✗ 登录体与抓包不一致：%s", bad)
			writeErr(w, http.StatusBadRequest, "invalid login parameter: "+bad)
			return
		}
	}

	s.mu.Lock()
	token, sess := s.token, s.sessID
	s.mu.Unlock()

	body := map[string]any{
		"Id": sess,
		"Oem": map[string]any{
			"Public": map[string]any{
				"Action":                  1,
				"AssignedPrivileges":      []string{"Login", "ConfigureComponents", "ConfigureSelf", "ConfigureUsers"},
				"OemPrivileges":           []string{"OemPowerControl", "OemRemoteMedia", "OemRemoteKvm", "OemSecureMgmt", "OemDebug", "OemDownloadLogs"},
				"PasswordChangeRequired":  false,
				"PasswordExpiredInterval": 94362,
				"Privilege":               "Administrator",
				"ServerAddr":              "192.168.10.79",
				"UserAddr":                "192.168.10.79",
				"X-Auth-Token":            token,
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/redfish/v1/SessionService/Sessions/"+sess)
	s.record(r, "登录成功，下发令牌", 200)
	s.logf("  ✓ 认证通过，令牌 %s，会话 %s", token, sess)
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(w, r, r.URL.Path) {
		return
	}
	s.record(r, "会话已释放", 204)
	w.WriteHeader(http.StatusNoContent)
}

/* ------------------------------ 资源读取 ------------------------------ */

func (s *Server) handleManagers(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	s.record(r, "资源集合", 200)
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.id": "/redfish/v1/Managers",
		"Members":   []any{map[string]any{"@odata.id": "/redfish/v1/Managers/1"}},
		"Name":      "Manager Collection",
	})
}

func (s *Server) handleManager(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	s.record(r, "管理器信息", 200)
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.id":   "/redfish/v1/Managers/1",
		"Id":          "1",
		"Name":        "Manager",
		"ManagerType": "BMC",
	})
}

func (s *Server) handleIfaces(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	s.record(r, "网卡集合", 200)
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.id":           "/redfish/v1/Managers/1/EthernetInterfaces",
		"@odata.type":         "#EthernetInterfaceCollection.EthernetInterfaceCollection",
		"Description":         "Collection of EthernetInterfaces for this Manager",
		"Members":             []any{map[string]any{"@odata.id": "/redfish/v1/Managers/1/EthernetInterfaces/eth0", "type": "dedicated"}},
		"Members@odata.count": 1,
		"Name":                "Ethernet Network Interface Collection",
		"Oem": map[string]any{
			"Public": map[string]any{
				"@odata.type": "#PublicEthernetInterface.v1_0_0.EthernetInterface",
				"DNSEnabled":  true,
				"NCSI": map[string]any{
					"Interface": "OCP0",
					"Mode":      "AutoFailover",
					"Port":      1,
				},
				"mDNSEnabled": false,
			},
		},
	})
}

func (s *Server) handleBond(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	s.record(r, "Bond 配置", 200)
	w.Header().Set("ETag", quote(randStr(32)))
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.id":   "/redfish/v1/Managers/1/Oem/Public/bondConfig",
		"@odata.type": "#BondConfig.BondConfig",
		"BondEnable":  false,
		"Description": "Bond config related Public OEM commands",
		"Id":          "bondConfig",
		"Name":        "BondConfig",
	})
}

func (s *Server) handleConfigLock(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	s.record(r, "配置锁定状态", 200)
	w.Header().Set("ETag", quote(randStr(27)))
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.id":   "/redfish/v1/Managers/1/Oem/BmcConfigLock",
		"@odata.type": "#OemBmcConfigLock.v0_0_1.OemBmcConfigLock",
		"BmcLockMode": "Disabled",
		"Id":          "1",
		"Name":        "BMC Config Lock",
	})
}

func (s *Server) handleNetworkProtocol(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	s.record(r, "网络协议配置", 200)
	writeJSON(w, http.StatusOK, map[string]any{
		"@odata.id": "/redfish/v1/Managers/1/NetworkProtocol",
		"Id":        "NetworkProtocol",
		"Name":      "Manager Network Protocol",
		"HTTPS":     map[string]any{"ProtocolEnabled": true, "Port": 443},
		"SSH":       map[string]any{"ProtocolEnabled": true, "Port": 22},
	})
}

/* ------------------------- eth0 读取与修改（核心） ------------------------- */

func (s *Server) handleEth0(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleEth0Get(w, r)
	case http.MethodPatch:
		s.handleEth0Patch(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleEth0Get(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	s.mu.Lock()
	etag := s.etag
	body := s.eth0BodyLocked()
	s.mu.Unlock()

	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	s.record(r, "读取网卡配置", 200)
	writeJSON(w, http.StatusOK, body)
}

type patchBody struct {
	IPv4Addresses []struct {
		Address       string `json:"Address"`
		SubnetMask    string `json:"SubnetMask"`
		Gateway       string `json:"Gateway"`
		AddressOrigin string `json:"AddressOrigin"`
	} `json:"IPv4Addresses"`
}

func (s *Server) handleEth0Patch(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}

	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	s.logf("  If-Match: %s", orNone(r.Header.Get("If-Match")))
	s.logf("  body: %s", strings.TrimSpace(string(raw)))

	s.mu.Lock()
	s.patchCnt++
	first := s.patchCnt == 1
	curEtag := s.etag
	oldIP, oldMask, oldGW := s.ip, s.mask, s.gw
	s.mu.Unlock()

	// 故障注入：首次 PATCH 返回 412，验证客户端会重取 ETag 重试
	if s.opts.FailFirstPatch && first {
		s.record(r, "故障注入：首次 PATCH 返回 412", 412)
		s.logf("  ⚑ 故障注入生效：首次 PATCH 返回 412 Precondition Failed")
		writeErr(w, http.StatusPreconditionFailed, "ETag mismatch")
		return
	}

	// 乐观锁校验
	if s.opts.RequireIfMatch {
		if got := r.Header.Get("If-Match"); got != curEtag {
			s.record(r, "If-Match 与当前 ETag 不符", 412)
			s.logf("  ✗ If-Match 不符：收到 %s，当前 %s", orNone(got), curEtag)
			writeErr(w, http.StatusPreconditionFailed, "ETag mismatch")
			return
		}
	}

	var pb patchBody
	if err := json.Unmarshal(raw, &pb); err != nil {
		s.record(r, "JSON 解析失败", 400)
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(pb.IPv4Addresses) != 1 {
		s.record(r, fmt.Sprintf("IPv4Addresses 数量为 %d，应为 1", len(pb.IPv4Addresses)), 400)
		writeErr(w, http.StatusBadRequest, "IPv4Addresses must contain exactly one entry")
		return
	}
	a := pb.IPv4Addresses[0]
	if a.AddressOrigin != "Static" {
		s.record(r, "AddressOrigin 必须为 Static", 400)
		writeErr(w, http.StatusBadRequest, "AddressOrigin must be Static")
		return
	}
	if ip := net.ParseIP(a.Address); ip == nil || ip.To4() == nil {
		s.record(r, "Address 非法："+a.Address, 400)
		writeErr(w, http.StatusBadRequest, "invalid Address: "+a.Address)
		return
	}
	if !validMask(a.SubnetMask) {
		s.record(r, "SubnetMask 非法："+a.SubnetMask, 400)
		writeErr(w, http.StatusBadRequest, "invalid SubnetMask: "+a.SubnetMask)
		return
	}
	if ip := net.ParseIP(a.Gateway); ip == nil || ip.To4() == nil {
		s.record(r, "Gateway 非法："+a.Gateway, 400)
		writeErr(w, http.StatusBadRequest, "invalid Gateway: "+a.Gateway)
		return
	}

	// 应用修改：地址变了，ETag 也必然变
	s.mu.Lock()
	s.ip, s.mask, s.gw = a.Address, a.SubnetMask, a.Gateway
	s.dhcp = false
	s.etag = quote(randStr(35))
	newEtag := s.etag
	if s.opts.DropAfterPatch {
		s.dead = true
	}
	s.mu.Unlock()

	s.record(r, "配置下发成功", 200)
	s.logf("  ✓ 管理口已更新：%s/%s gw %s  →  %s/%s gw %s",
		oldIP, oldMask, oldGW, a.Address, a.SubnetMask, a.Gateway)
	s.logf("    新 ETag：%s", newEtag)
	if s.opts.DropAfterPatch {
		s.logf("    ⚑ DropAfterPatch 已生效：之后的 Redfish 请求将被直接掐断")
	}
	if s.onChange != nil {
		s.onChange(oldIP, a.Address, a.SubnetMask, a.Gateway)
	}

	// 抓包里 PATCH 返回 200 且响应体为空
	w.WriteHeader(http.StatusOK)
}

func (s *Server) eth0BodyLocked() map[string]any {
	addr := map[string]any{
		"Address":       s.ip,
		"AddressOrigin": "Static",
		"Gateway":       s.gw,
		"SubnetMask":    s.mask,
	}
	return map[string]any{
		"@odata.context": "/redfish/v1/$metadata#EthernetInterface.EthernetInterface",
		"@odata.id":      "/redfish/v1/Managers/1/EthernetInterfaces/eth0",
		"@odata.type":    "#EthernetInterface.v1_11_0.EthernetInterface",
		"DHCPv4": map[string]any{
			"DHCPEnabled":   s.dhcp,
			"UseDNSServers": true,
			"UseDomainName": true,
			"UseNTPServers": false,
		},
		"DHCPv6": map[string]any{
			"OperatingMode": "Disabled",
			"UseDNSServers": true,
			"UseDomainName": true,
			"UseNTPServers": false,
		},
		"Description":            "Management Network Interface",
		"HostName":               "MOCKBMC001",
		"IPv4Addresses":          []any{addr},
		"IPv4StaticAddresses":    []any{addr},
		"IPv6AddressPolicyTable": []any{},
		"IPv6Addresses": []any{map[string]any{
			"Address":       "fe80::366f:11ff:fe6a:3076",
			"AddressOrigin": "LinkLocal",
			"PrefixLength":  64,
		}},
		"IPv6DefaultGateway":        "0:0:0:0:0:0:0:0",
		"IPv6StaticAddresses":       []any{},
		"IPv6StaticDefaultGateways": []any{},
		"Id":                        "eth0",
		"InterfaceEnabled":          true,
		"LinkStatus":                "LinkUp",
		"MACAddress":                "34:6f:11:6a:30:76",
		"Name":                      "Manager Ethernet Interface",
		"NameServers":               []any{},
		"Oem": map[string]any{
			"Public": map[string]any{
				"@odata.id":   "/redfish/v1/Managers/1/EthernetInterfaces/eth0#/Oem/Public",
				"@odata.type": "#OemEthernetInterface.EthernetInterface",
				"DNS": map[string]any{
					"DomainManual":               false,
					"DomainName":                 "",
					"HostNameAutoConfigedEnable": true,
					"Manual":                     false,
					"NsupdateEnable":             false,
					"Priority":                   "IPv4",
					"RegistionEnabled":           true,
					"RegistionOption":            "",
					"mDNSEnable":                 false,
				},
				"EnableStatus": "ipv4",
			},
		},
		"PermanentMACAddress": "34:6f:11:6a:30:76",
		"SpeedMbps":           1000,
		"StaticNameServers":   []any{},
		"Status": map[string]any{
			"Health":       "OK",
			"HealthRollup": "OK",
			"State":        "Enabled",
		},
		"VLAN":  map[string]any{"VLANEnable": false, "VLANId": 0},
		"VLANs": map[string]any{"@odata.id": "/redfish/v1/Managers/1/EthernetInterfaces/eth0/VLANs"},
	}
}

/* ------------------------------ 鉴权与守卫 ------------------------------ */

// guard 做「掐线判断 + 鉴权 + 人为延迟」，返回 true 表示可以继续处理。
func (s *Server) guard(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	dead := s.dead
	s.mu.Unlock()

	// 只在 HTTPS 的 Redfish 接口上模拟断连，面板（HTTP）保持可用
	if dead && r.TLS != nil && strings.HasPrefix(r.URL.Path, "/redfish/") {
		s.hardClose(w)
		return false
	}

	if s.opts.Latency > 0 {
		time.Sleep(s.opts.Latency)
	}

	if !s.authOK(w, r, "") {
		return false
	}
	return true
}

// authOK 校验认证头；失败时已写好响应并返回 false。
func (s *Server) authOK(w http.ResponseWriter, r *http.Request, note string) bool {
	present := []string{}
	x1 := r.Header.Get("X-Auth-Token")
	x2 := r.Header.Get("X-XSRF-TOKEN")
	bearer := ""
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		bearer = strings.TrimPrefix(v, "Bearer ")
	}
	if x1 != "" {
		present = append(present, AuthXAuth)
	}
	if x2 != "" {
		present = append(present, AuthXSRF)
	}
	if bearer != "" {
		present = append(present, AuthBearer)
	}

	s.mu.Lock()
	expect := s.token
	s.mu.Unlock()

	s.logf("  认证头：%s", describeAuth(x1, x2, bearer))

	if len(present) == 0 {
		s.record(r, "缺少认证头", 401)
		s.logf("  ✗ 请求未携带任何认证头")
		writeErr(w, http.StatusUnauthorized, "authentication required")
		return false
	}

	// 严格模式：带了多种认证头就拒绝（用来逼出客户端的降级逻辑）
	if s.opts.StrictOneAuthHeader && len(present) > 1 {
		s.record(r, fmt.Sprintf("带了 %d 种认证头，严格模式只允许一种", len(present)), 401)
		s.logf("  ✗ 严格模式：请求带了 %d 种认证头，只允许一种", len(present))
		writeErr(w, http.StatusUnauthorized, "exactly one authentication header is allowed")
		return false
	}

	// 服务端只认指定形式
	var token string
	switch s.opts.AuthMode {
	case AuthXAuth:
		token = x1
	case AuthXSRF:
		token = x2
	case AuthBearer:
		token = bearer
	default: // AuthAny：按 X-Auth-Token → X-XSRF-TOKEN → Bearer 依次取
		token = firstNonEmpty(x1, x2, bearer)
	}

	if token == "" {
		s.record(r, "服务端只认 "+s.opts.AuthMode+"，但该头缺失", 401)
		s.logf("  ✗ 服务端只认 %s，本次未提供", s.opts.AuthMode)
		writeErr(w, http.StatusUnauthorized, "expected auth header "+s.opts.AuthMode+" is missing")
		return false
	}
	if token != expect {
		s.record(r, "令牌无效", 401)
		s.logf("  ✗ 令牌无效")
		writeErr(w, http.StatusUnauthorized, "invalid token")
		return false
	}
	return true
}

// hardClose 直接掐断 TCP 连接，模拟设备切换地址后的失联。
func (s *Server) hardClose(w http.ResponseWriter) {
	s.logf("  ✗ 连接已被掐断（模拟设备已切换地址）")
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

/* ------------------------------ 状态面板 ------------------------------ */

func (s *Server) handleMockState(w http.ResponseWriter, r *http.Request) {
	ip, mask, gw, etag, dhcp := s.State()
	s.mu.Lock()
	hist := make([]ReqEntry, len(s.history))
	copy(hist, s.history)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"current": map[string]any{"ip": ip, "mask": mask, "gateway": gw, "dhcp": dhcp, "etag": etag},
		"history": hist,
	})
}

func (s *Server) handleMockReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	s.mu.Lock()
	s.ip, s.mask, s.gw = s.opts.IP, s.opts.Mask, s.opts.GW
	s.dhcp = s.opts.DHCP
	s.etag = quote(randStr(35))
	s.token = randStr(32)
	s.sessID = randStr(10)
	s.loginCnt, s.patchCnt = 0, 0
	s.dead = false
	s.history = nil
	s.mu.Unlock()

	s.logf("↺ 状态已重置：管理口 %s/%s gw %s", s.opts.IP, s.opts.Mask, s.opts.GW)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) writeDashboard(w http.ResponseWriter, r *http.Request) {
	ip, mask, gw, etag, dhcp := s.State()
	s.mu.Lock()
	hist := make([]ReqEntry, len(s.history))
	copy(hist, s.history)
	dead := s.dead
	s.mu.Unlock()

	var rows strings.Builder
	for i := len(hist) - 1; i >= 0; i-- {
		e := hist[i]
		cls := "ok"
		if e.Status >= 400 {
			cls = "bad"
		}
		fmt.Fprintf(&rows, "<tr class=\"%s\"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>",
			cls, html.EscapeString(e.At), html.EscapeString(e.Method),
			html.EscapeString(e.Path), html.EscapeString(e.Auth), e.Status, html.EscapeString(e.Note))
	}
	if rows.Len() == 0 {
		rows.WriteString(`<tr><td colspan="6" class="muted">暂无请求</td></tr>`)
	}

	dhcpText := "否（静态）"
	if dhcp {
		dhcpText = "是"
	}
	deadText := "正常"
	if dead {
		deadText = "已掐断（模拟设备已切走地址）"
	}

	page := `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="2">
<title>模拟 BMC 状态面板</title>
<style>
 :root{color-scheme:light dark}
 body{font-family:"Microsoft YaHei UI",system-ui,sans-serif;margin:0;padding:24px;background:#f6f7f9;color:#1d2129}
 .card{background:#fff;border:1px solid #e5e6eb;border-radius:10px;padding:18px 20px;margin-bottom:18px}
 h1{font-size:18px;margin:0 0 14px}
 h2{font-size:14px;margin:0 0 10px;color:#4e5969;font-weight:600}
 .kv{display:grid;grid-template-columns:120px 1fr;gap:8px 12px;font-size:14px}
 .kv b{color:#4e5969;font-weight:500}
 code{font-family:Consolas,monospace;background:#f2f3f5;padding:2px 6px;border-radius:4px;font-size:13px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #f2f3f5}
 th{color:#4e5969;font-weight:600;background:#fafafa}
 tr.bad td{color:#c9302c}
 .muted{color:#86909c}
 .tag{display:inline-block;background:#e8f3ff;color:#1668dc;border-radius:4px;padding:1px 8px;font-size:12px;margin-left:8px}
 @media (prefers-color-scheme:dark){
  body{background:#17171a;color:#e5e6eb}
  .card{background:#1f1f24;border-color:#2e2e34}
  h2,.kv b,th{color:#a9aeb8}
  code{background:#2a2a30}
  th{background:#232329}
  td,th{border-color:#2a2a30}
  tr.bad td{color:#f98a8a}
  .muted{color:#6b7280}
  .tag{background:#1b2a41;color:#69b1ff}
 }
</style></head><body>
<div class="card">
 <h1>模拟 BMC 状态面板 <span class="tag">每 2 秒自动刷新</span></h1>
 <div class="kv">
  <b>管理口 IP</b><span><code>%s</code></span>
  <b>子网掩码</b><span><code>%s</code></span>
  <b>默认网关</b><span><code>%s</code></span>
  <b>DHCP</b><span>%s</span>
  <b>当前 ETag</b><span><code>%s</code></span>
  <b>接口状态</b><span>%s</span>
 </div>
</div>
<div class="card">
 <h2>请求记录（最新在上）</h2>
 <table>
  <thead><tr><th>时间</th><th>方法</th><th>路径</th><th>认证头</th><th>状态</th><th>说明</th></tr></thead>
  <tbody>%s</tbody>
 </table>
</div>
</body></html>`

	_, _ = fmt.Fprintf(w, page, ip, mask, gw, dhcpText, etag, deadText, rows.String())
}

/* -------------------------------- 工具 -------------------------------- */

func (s *Server) record(r *http.Request, note string, status int) {
	auth := "—"
	if v := r.Header.Get("X-Auth-Token"); v != "" {
		auth = "X-Auth-Token"
	}
	if v := r.Header.Get("X-XSRF-TOKEN"); v != "" {
		if auth == "—" {
			auth = "X-XSRF-TOKEN"
		} else {
			auth += " + X-XSRF-TOKEN"
		}
	}
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		if auth == "—" {
			auth = "Bearer"
		} else {
			auth += " + Bearer"
		}
	}

	s.mu.Lock()
	s.history = append(s.history, ReqEntry{
		At:     time.Now().Format("15:04:05"),
		Method: r.Method,
		Path:   r.URL.Path,
		Auth:   auth,
		Note:   note,
		Status: status,
	})
	if len(s.history) > 200 {
		s.history = s.history[len(s.history)-200:]
	}
	s.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// writeErr 输出与真实设备同风格的错误体。
func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "{\"error\":{\"code\":\"Base.1.0.GeneralError\",\"message\":%q}}\n", msg)
}

func describeAuth(x1, x2, bearer string) string {
	parts := []string{}
	if x1 != "" {
		parts = append(parts, "X-Auth-Token="+short(x1))
	}
	if x2 != "" {
		parts = append(parts, "X-XSRF-TOKEN="+short(x2))
	}
	if bearer != "" {
		parts = append(parts, "Bearer="+short(bearer))
	}
	if len(parts) == 0 {
		return "（无）"
	}
	return strings.Join(parts, " | ")
}

func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8] + "…"
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "（无）"
	}
	return s
}

func quote(s string) string { return `"` + s + `"` }

// validMask 校验点分十进制掩码是否为合法的连续掩码。
func validMask(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return false
	}
	ones, bits := net.IPMask(ip.To4()).Size()
	return bits == 32 && ones > 0
}

const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randStr(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("x", n)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// selfSignedCert 生成自签证书，让模拟端也能走真实 TLS 链路
// （真实 BMC 用的就是自签名证书，客户端必须能正确跳过校验）。
func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mock BMC", Organization: []string{"MockBMC"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
