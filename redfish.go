package main

// redfish.go —— 深信服 BMC（Redfish 接口）客户端
//
// 协议依据 192.168.10.10.har 抓包还原：
//
//	1) 登录   POST /redfish/v1/SessionService/Sessions
//	          body: {"UserName":"..","Password":"..","Oem":{"Public":{"EncryptFlag":false,"LoginTag":<int>,"SessionType":"WebUI"}}}
//	          resp: Oem.Public["X-Auth-Token"] 即为后续请求所需的令牌
//	2) 查询   GET  /redfish/v1/Managers/1/EthernetInterfaces/eth0
//	          resp header ETag 用于乐观锁
//	3) 修改   PATCH /redfish/v1/Managers/1/EthernetInterfaces/eth0
//	          header: If-Match: "<ETag>"
//	          body:   {"IPv4Addresses":[{"AddressOrigin":"Static","Address":"..","SubnetMask":"..","Gateway":".."}]}
//	4) 登出   DELETE /redfish/v1/SessionService/Sessions/{Id}

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

// LogFunc 日志回调，GUI 用它把过程输出到日志框。
type LogFunc func(format string, args ...interface{})

const (
	pathSessions = "/redfish/v1/SessionService/Sessions"
	pathManagers = "/redfish/v1/Managers"

	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"
)

// 各类超时。真机不可达时 Windows 默认要等约 21 秒才报错，
// 对交互式工具太久了，这里把建连时间压到 8 秒。
//
// 声明成变量是为了让单元测试能临时调小。
var (
	DialTimeout           = 300 * time.Second
	TLSHandshakeTimeout   = 8 * time.Second
	ResponseHeaderTimeout = 20 * time.Second
	RequestTimeout        = 30 * time.Second
)

// IsCanceled 判断错误是否来自「用户点了停止」。
func IsCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}

// IPv4Conf 对应 Redfish 的 IPv4Addresses 元素。
type IPv4Conf struct {
	Address       string `json:"Address"`
	SubnetMask    string `json:"SubnetMask"`
	Gateway       string `json:"Gateway"`
	AddressOrigin string `json:"AddressOrigin"`
}

// IfaceState 是网卡当前的完整状态（含乐观锁 ETag 与资源路径）。
type IfaceState struct {
	Path        string // 例如 /redfish/v1/Managers/1/EthernetInterfaces/eth0
	ID          string // 例如 eth0
	ETag        string
	DHCPEnabled bool
	IPv4        IPv4Conf
}

// Client 是 BMC 的 Redfish 会话客户端。
type Client struct {
	base    string // 例如 https://192.168.10.10
	user    string
	pass    string
	http    *http.Client
	token   string // X-Auth-Token / X-XSRF-TOKEN
	session string // 会话 Id，用于登出
	loc     string // 登出用的 Location（若服务端返回）
	log     LogFunc
	ctx     context.Context // 用于「停止」：取消后所有在途请求立即返回

	// authMode 决定令牌以哪种请求头下发。
	// 抓包中该令牌以 X-XSRF-TOKEN 出现，但标准 Redfish 用 X-Auth-Token，
	// 不同固件版本可能只认其中一种，因此这里做成可自动降级重试。
	// 0=两种都带（默认） 1=仅 X-Auth-Token 2=仅 X-XSRF-TOKEN 3=Authorization: Bearer
	authMode int
}

// authModeName 用于日志展示。
func authModeName(mode int) string {
	switch mode {
	case 1:
		return "X-Auth-Token"
	case 2:
		return "X-XSRF-TOKEN"
	case 3:
		return "Authorization: Bearer"
	}
	return "X-Auth-Token + X-XSRF-TOKEN"
}

// applyAuthHeader 按当前 authMode 写认证头。
func (c *Client) applyAuthHeader(req *http.Request) {
	if c.token == "" {
		return
	}
	switch c.authMode {
	case 1:
		req.Header.Set("X-Auth-Token", c.token)
	case 2:
		req.Header.Set("X-XSRF-TOKEN", c.token)
	case 3:
		req.Header.Set("Authorization", "Bearer "+c.token)
	default:
		req.Header.Set("X-Auth-Token", c.token)
		req.Header.Set("X-XSRF-TOKEN", c.token)
	}
}

// NewClient 构造客户端。host 允许写成 "192.168.10.10"、"192.168.10.10:443"
// 或 "https://192.168.10.10"。port 仅在 host 未自带端口时生效。
func NewClient(host, port, user, pass string, log LogFunc) *Client {
	if log == nil {
		log = func(string, ...interface{}) {}
	}

	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimSuffix(h, "/")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	// 未带端口时按需补端口
	if _, _, err := net.SplitHostPort(h); err != nil {
		p := strings.TrimSpace(port)
		if p == "" {
			p = "443"
		}
		if p != "443" && p != "80" {
			h = net.JoinHostPort(h, p)
		}
	}

	dialer := &net.Dialer{Timeout: DialTimeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// BMC 在内网，禁止走系统代理，否则会被代理拦截
		Proxy:       nil,
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // BMC 使用自签名证书
			MinVersion:         tls.VersionTLS10,
		},
		// 置空即以纯 HTTP/1.1 通信，避免个别 BMC 对 h2 支持不佳
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		ResponseHeaderTimeout: ResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConnsPerHost:   4,
	}
	jar, _ := cookiejar.New(nil)

	return &Client{
		base: "https://" + h,
		user: user,
		pass: pass,
		http: &http.Client{Transport: tr, Jar: jar, Timeout: RequestTimeout},
		log:  log,
		ctx:  context.Background(),
	}
}

// WithContext 绑定一个可取消的上下文。
// GUI 的「停止」按钮通过取消它来立即中断在途请求。
func (c *Client) WithContext(ctx context.Context) *Client {
	if ctx == nil {
		ctx = context.Background()
	}
	c.ctx = ctx
	return c
}

// BaseURL 返回归一化后的基地址，便于日志展示。
func (c *Client) BaseURL() string { return c.base }

/* ------------------------------ 底层收发 ------------------------------ */

func (c *Client) do(method, path string, body []byte, extra map[string]string) (int, http.Header, []byte, error) {
	// 上下文被取消时直接短路，避免被取消后还去建连
	if err := c.ctx.Err(); err != nil {
		return 0, nil, nil, err
	}

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(c.ctx, method, c.base+path, rdr)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Request-Id", newRequestID())
	req.Header.Set("Cache-Control", "max-age=0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.applyAuthHeader(req)
	for k, v := range extra {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, simplifyNetErr(err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	return resp.StatusCode, resp.Header, data, nil
}

// simplifyNetErr 把底层网络错误换成更容易看懂的提示。
// 注意 Windows 与 Linux 的措辞不同，这里两边都覆盖。
//
// 判断顺序很重要：Windows 的「连接超时」文案里也含 connectex，
// 若先匹配 connectex 就会把超时误报成"连接被拒绝"。
func simplifyNetErr(err error) error {
	if IsCanceled(err) {
		return fmt.Errorf("操作已停止：%w", err)
	}

	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "tls:") && (strings.Contains(s, "handshake") || strings.Contains(s, "first record")):
		return fmt.Errorf("TLS 握手失败（端口可能不是 HTTPS，或服务端仅支持过旧的加密套件）：%w", err)
	case strings.Contains(s, "x509") || strings.Contains(s, "certificate"):
		return fmt.Errorf("证书校验失败：%w", err)

	// —— 超时/无响应 ——（必须放在"连接被拒绝"之前）
	case strings.Contains(s, "i/o timeout"),
		strings.Contains(s, "deadline exceeded"),
		strings.Contains(s, "timed out"),
		strings.Contains(s, "did not properly respond"), // Windows 建连超时
		strings.Contains(s, "failed to respond"),
		strings.Contains(s, "connection attempt failed"):
		return fmt.Errorf("连接超时：设备无响应，请确认 IP/网关是否正确、设备是否在线：%w", err)

	// —— 拒绝/不可达 ——
	case strings.Contains(s, "actively refused"), // Windows
		strings.Contains(s, "connection refused"): // Linux/macOS
		return fmt.Errorf("连接被拒绝，请确认设备地址/端口是否正确、服务是否在监听：%w", err)
	case strings.Contains(s, "network is unreachable"),
		strings.Contains(s, "no route to host"):
		return fmt.Errorf("网络不可达，请检查本机 IP/网关与路由：%w", err)
	case strings.Contains(s, "no such host"),
		strings.Contains(s, "name or service not known"):
		return fmt.Errorf("主机名无法解析：%w", err)
	}
	return err
}

/* -------------------------------- 登录 -------------------------------- */

type loginPub struct {
	EncryptFlag bool   `json:"EncryptFlag"`
	LoginTag    int32  `json:"LoginTag"`
	SessionType string `json:"SessionType"`
}

type loginOem struct {
	Public loginPub `json:"Public"`
}

type loginReq struct {
	UserName string    `json:"UserName"`
	Password string    `json:"Password"`
	Oem      *loginOem `json:"Oem,omitempty"`
}

type loginResp struct {
	Id  string `json:"Id"`
	Oem struct {
		Public struct {
			XAuthToken string `json:"X-Auth-Token"`
			Privilege  string `json:"Privilege"`
		} `json:"Public"`
	} `json:"Oem"`
}

// Login 建立会话。为兼容不同固件版本，按「标准 → 简化 → LoginTag=0」依次降级重试。
func (c *Client) Login() error {
	c.token, c.session, c.loc = "", "", ""

	attempts := []struct {
		desc string
		body loginReq
	}{
		{"标准登录（带 Oem 参数）", loginReq{c.user, c.pass, &loginOem{loginPub{false, randInt31(), "WebUI"}}}},
		{"简化登录（不带 Oem 参数）", loginReq{c.user, c.pass, nil}},
		{"兼容登录（LoginTag=0）", loginReq{c.user, c.pass, &loginOem{loginPub{false, 0, "WebUI"}}}},
	}

	var lastErr error
	for i, at := range attempts {
		payload, _ := json.Marshal(at.body)
		code, hdr, data, err := c.do(http.MethodPost, pathSessions, payload, nil)
		if err != nil {
			return fmt.Errorf("登录请求发送失败：%w", err)
		}
		if code == http.StatusOK || code == http.StatusCreated {
			var lr loginResp
			_ = json.Unmarshal(data, &lr)

			token := lr.Oem.Public.XAuthToken
			if token == "" {
				token = hdr.Get("X-Auth-Token")
			}
			if token == "" {
				token = hdr.Get("X-XSRF-TOKEN")
			}
			if token == "" {
				lastErr = fmt.Errorf("登录成功但响应中未解析到令牌")
				c.log("  [%d] %s：响应里没有令牌，继续尝试其它登录方式", i+1, at.desc)
				continue
			}

			c.token = token
			c.session = lr.Id
			c.loc = hdr.Get("Location")
			priv := lr.Oem.Public.Privilege
			if priv == "" {
				priv = "未知"
			}
			c.log("  [%d] %s：成功，权限 %s，会话 %s", i+1, at.desc, priv, orDash(c.session))
			return nil
		}

		msg := extractErrMsg(data)
		lastErr = fmt.Errorf("HTTP %d %s", code, msg)
		c.log("  [%d] %s：失败（HTTP %d %s）", i+1, at.desc, code, msg)
		if code == http.StatusUnauthorized || code == http.StatusForbidden {
			// 账号密码问题，换登录体也没用，直接停
			return fmt.Errorf("认证失败（HTTP %d）：请检查用户名/密码%s", code, hintMsg(msg))
		}
	}
	return fmt.Errorf("登录失败：%v", lastErr)
}

// Logout 主动释放会话，失败不影响主流程。
func (c *Client) Logout() {
	if c.token == "" {
		return
	}
	// 上下文已被取消（用户点了停止）时不必再发请求，直接放弃本地会话
	if c.ctx != nil && c.ctx.Err() != nil {
		c.log("  已中断，跳过会话释放（会话会由设备侧超时回收）")
		c.token, c.session, c.loc = "", "", ""
		return
	}
	target := c.loc
	if target == "" && c.session != "" {
		target = pathSessions + "/" + c.session
	}
	if target == "" {
		return
	}
	if strings.HasPrefix(target, "http") {
		// Location 是绝对地址时，转成相对路径
		if u := strings.Index(target, "//"); u >= 0 {
			if p := strings.IndexByte(target[u+2:], '/'); p >= 0 {
				target = target[u+2+p:]
			}
		}
	}
	if code, _, _, err := c.do(http.MethodDelete, target, nil, nil); err != nil {
		c.log("  会话释放失败（忽略）：%v", err)
	} else if code >= 400 {
		c.log("  会话释放返回 HTTP %d（忽略）", code)
	} else {
		c.log("  会话已释放")
	}
	c.token, c.session, c.loc = "", "", ""
}

/* ------------------------------ 网卡读写 ------------------------------ */

// get 发起 GET。若服务端返回 401/403（说明它不认当前的认证头形式），
// 自动换用其它几种形式重试，成功后记住可用形式。
func (c *Client) get(path string) (int, http.Header, []byte, error) {
	code, hdr, data, err := c.do(http.MethodGet, path, nil, nil)
	if err != nil || (code != http.StatusUnauthorized && code != http.StatusForbidden) {
		return code, hdr, data, err
	}

	start := c.authMode
	for _, mode := range []int{1, 2, 3, 0} {
		if mode == start {
			continue
		}
		c.authMode = mode
		code, hdr, data, err = c.do(http.MethodGet, path, nil, nil)
		if err != nil {
			return code, hdr, data, err
		}
		if code == http.StatusOK {
			c.log("  认证头自动切换为 %s 后成功", authModeName(mode))
			return code, hdr, data, nil
		}
	}
	c.authMode = start
	return code, hdr, data, nil
}

// resolveIface 自动探测管理口资源路径，探测不到时回落到抓包中的固定路径。
func (c *Client) resolveIface() string {
	const fallback = "/redfish/v1/Managers/1/EthernetInterfaces/eth0"

	managerPath := ""
	if code, _, data, err := c.get(pathManagers); err == nil && code == http.StatusOK {
		managerPath = firstMemberPath(data)
	}
	if managerPath == "" {
		managerPath = "/redfish/v1/Managers/1"
	}

	ifacePath := ""
	if code, _, data, err := c.get(managerPath + "/EthernetInterfaces"); err == nil && code == http.StatusOK {
		ifacePath = firstMemberPath(data)
	}
	if ifacePath == "" {
		ifacePath = managerPath + "/EthernetInterfaces/eth0"
	}

	if ifacePath != fallback {
		c.log("  自动探测到管理口资源：%s", ifacePath)
	}
	return ifacePath
}

// ReadIface 读取管理口当前 IPv4 配置与 ETag。
func (c *Client) ReadIface() (*IfaceState, error) {
	path := c.resolveIface()

	code, hdr, data, err := c.get(path)
	if err != nil {
		return nil, fmt.Errorf("读取网卡配置失败：%w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("读取网卡配置失败：HTTP %d %s", code, extractErrMsg(data))
	}

	var raw struct {
		Id     string `json:"Id"`
		DHCPv4 struct {
			DHCPEnabled bool `json:"DHCPEnabled"`
		} `json:"DHCPv4"`
		IPv4Addresses []IPv4Conf `json:"IPv4Addresses"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("网卡配置解析失败：%w", err)
	}

	st := &IfaceState{
		Path:        path,
		ID:          raw.Id,
		ETag:        hdr.Get("ETag"),
		DHCPEnabled: raw.DHCPv4.DHCPEnabled,
	}
	if len(raw.IPv4Addresses) > 0 {
		st.IPv4 = raw.IPv4Addresses[0]
	}
	return st, nil
}

// ApplyIPv4 通过 PATCH 下发静态 IPv4 配置。etag 为空时不带 If-Match。
func (c *Client) ApplyIPv4(st *IfaceState, address, mask, gateway string) error {
	payload := map[string]interface{}{
		"IPv4Addresses": []IPv4Conf{{
			AddressOrigin: "Static",
			Address:       address,
			SubnetMask:    mask,
			Gateway:       gateway,
		}},
	}
	body, _ := json.Marshal(payload)
	c.log("  → PATCH %s", st.Path)
	c.log("    请求体 %s", string(body))

	send := func(etag string) (int, []byte, error) {
		var extra map[string]string
		if etag != "" {
			extra = map[string]string{"If-Match": etag}
		}
		code, _, data, err := c.do(http.MethodPatch, st.Path, body, extra)
		return code, data, err
	}

	code, data, err := send(st.ETag)
	if err != nil {
		return fmt.Errorf("下发配置失败：%w", err)
	}

	// 412：本地 ETag 过期（例如页面/程序之间配置被改过），重取一次再试
	if code == http.StatusPreconditionFailed {
		c.log("  ETag 已过期（HTTP 412），重新读取后重试一次…")
		fresh, e := c.ReadIface()
		if e != nil {
			return fmt.Errorf("配置已被他人修改且重新读取失败：%w", e)
		}
		st.ETag = fresh.ETag
		code, data, err = send(fresh.ETag)
		if err != nil {
			return fmt.Errorf("下发配置失败：%w", err)
		}
	}

	if code != http.StatusOK && code != http.StatusNoContent && code != http.StatusAccepted {
		return fmt.Errorf("修改被拒绝：HTTP %d %s", code, extractErrMsg(data))
	}
	c.log("  ✓ 服务端已接受修改（HTTP %d）", code)
	return nil
}

/* -------------------------------- 工具 -------------------------------- */

// firstMemberPath 从 {"Members":[{"@odata.id":".."}]} 中取出第一个资源路径。
func firstMemberPath(data []byte) string {
	var v struct {
		Members []struct {
			ODataID string `json:"@odata.id"`
		} `json:"Members"`
	}
	if json.Unmarshal(data, &v) != nil {
		return ""
	}
	for _, m := range v.Members {
		if m.ODataID != "" {
			return m.ODataID
		}
	}
	return ""
}

// extractErrMsg 尽力从错误响应里挖出一句人类可读的信息。
func extractErrMsg(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var m map[string]interface{}
	if json.Unmarshal(data, &m) == nil {
		for _, k := range []string{"error", "Message", "message", "MessageId", "detail"} {
			if v, ok := m[k]; ok {
				switch t := v.(type) {
				case string:
					if t != "" {
						return tone(t)
					}
				case map[string]interface{}:
					if s, ok := t["message"].(string); ok && s != "" {
						return tone(s)
					}
					if s, ok := t["Message"].(string); ok && s != "" {
						return tone(s)
					}
				}
			}
		}
	}
	s := strings.TrimSpace(string(data))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return tone(s)
}

// tone 去掉正文里的换行/tab，避免日志被撑乱。
func tone(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.TrimSpace(s)
}

func hintMsg(msg string) string {
	if msg == "" {
		return ""
	}
	return "（服务端提示：" + msg + "）"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randInt31() int32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	v := int32(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) & 0x7fffffff
	if v == 0 {
		v = 1
	}
	return v
}

/* ------------------------------ 输入校验 ------------------------------ */

// ParseIPv4 校验并解析点分十进制 IPv4。
func ParseIPv4(s string) (net.IP, error) {
	s = strings.TrimSpace(s)
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("不是合法的 IP 地址：%s", s)
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("这里只支持 IPv4：%s", s)
	}
	return v4, nil
}

// ParseMask 校验并解析子网掩码。
func ParseMask(s string) (net.IPMask, error) {
	s = strings.TrimSpace(s)
	ip, err := ParseIPv4(s)
	if err != nil {
		return nil, fmt.Errorf("子网掩码不合法：%s", s)
	}
	m := net.IPMask(ip)
	ones, bits := m.Size()
	if bits != 32 || ones == 0 {
		return nil, fmt.Errorf("子网掩码不是合法的掩码序列：%s", s)
	}
	return m, nil
}

// SameSubnet 判断两个地址是否在同一网段。
func SameSubnet(a, b net.IP, mask net.IPMask) bool {
	return (&net.IPNet{IP: a.Mask(mask), Mask: mask}).Contains(b)
}
