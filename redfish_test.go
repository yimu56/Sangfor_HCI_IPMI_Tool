package main

// redfish_test.go —— 用本地 mock 服务器复现深信服 BMC 的 Redfish 行为，
// 校验请求体、令牌传递、ETag/If-Match 以及降级重试逻辑。
// 断言依据来自 192.168.10.10.har 抓包。

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const eth0JSON = `{
  "Id": "eth0",
  "DHCPv4": {"DHCPEnabled": false},
  "IPv4Addresses": [
    {"Address": "192.168.10.10", "SubnetMask": "255.255.255.0",
     "Gateway": "192.168.10.1", "AddressOrigin": "Static"}
  ]
}`

// newTestClient 返回指向 mock 服务器的客户端（测试里直接改写 base 走 http）。
func newTestClient(t *testing.T, url, user, pass string) *Client {
	t.Helper()
	c := NewClient("127.0.0.1", "", user, pass, func(string, ...interface{}) {})
	c.base = strings.TrimSuffix(url, "/")
	return c
}

// mockBMC 搭一个最小可用的 BMC。
type mockBMC struct {
	t *testing.T

	mu             sync.Mutex
	loginBodies    []map[string]interface{}
	patchBody      map[string]interface{}
	ifMatchSeen    string
	seenAuthHeader string
	seenXSRFHeader string
	sessionDeleted bool

	rejectOemLogin bool // 模拟老固件不接受 Oem 参数
	failFirstPatch bool // 模拟第一次 PATCH 返回 412
	patchCount     int
	etag           string
}

func (m *mockBMC) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/redfish/v1/SessionService/Sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body map[string]interface{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		m.mu.Lock()
		m.loginBodies = append(m.loginBodies, body)
		m.mu.Unlock()

		if m.rejectOemLogin {
			if _, hasOem := body["Oem"]; hasOem {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"message":"invalid parameter Oem"}}`))
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Id":"vR4Zxvd1hs","Oem":{"Public":{
              "Privilege":"Administrator","X-Auth-Token":"bZGSiwnBka7zO6mdtDSiA7OflBT1YkEw"}}}`))
	})

	// 登出：DELETE /redfish/v1/SessionService/Sessions/{id}
	mux.HandleFunc("/redfish/v1/SessionService/Sessions/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/vR4Zxvd1hs") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		m.mu.Lock()
		m.sessionDeleted = true
		m.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/1"}]}`))
	})
	mux.HandleFunc("/redfish/v1/Managers/1/EthernetInterfaces", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces/eth0"}]}`))
	})
	mux.HandleFunc("/redfish/v1/Managers/1/EthernetInterfaces/eth0", func(w http.ResponseWriter, r *http.Request) {
		m.recordAuth(r)
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", m.etag)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(eth0JSON))
		case http.MethodPatch:
			raw, _ := io.ReadAll(r.Body)
			var body map[string]interface{}
			_ = json.Unmarshal(raw, &body)

			m.mu.Lock()
			m.patchCount++
			m.patchBody = body
			m.ifMatchSeen = r.Header.Get("If-Match")
			first := m.patchCount == 1
			m.mu.Unlock()

			if m.failFirstPatch && first {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			w.WriteHeader(http.StatusOK)
		}
	})

	return mux
}

func (m *mockBMC) recordAuth(r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v := r.Header.Get("X-Auth-Token"); v != "" {
		m.seenAuthHeader = v
	}
	if v := r.Header.Get("X-XSRF-TOKEN"); v != "" {
		m.seenXSRFHeader = v
	}
}

/* --------------------------------- 测试 --------------------------------- */

func TestFullChangeFlow(t *testing.T) {
	mock := &mockBMC{t: t, etag: `"Kilw1sfLoqLLEAA20iKROBq0raJvWfiyIJP"`}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	c := newTestClient(t, srv.URL, "sangfor", "S#AN$6fo81r")

	// 1) 登录
	if err := c.Login(); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if c.token != "bZGSiwnBka7zO6mdtDSiA7OflBT1YkEw" {
		t.Fatalf("令牌解析错误: %q", c.token)
	}

	// 登录体必须与抓包一致：Oem.Public{EncryptFlag:false, SessionType:WebUI, LoginTag≠0}
	lb := mock.loginBodies[0]
	if lb["UserName"] != "sangfor" || lb["Password"] != "S#AN$6fo81r" {
		t.Fatalf("登录体账号密码错误: %v", lb)
	}
	oem, ok := lb["Oem"].(map[string]interface{})
	if !ok {
		t.Fatalf("登录体缺少 Oem 节点: %v", lb)
	}
	pub := oem["Public"].(map[string]interface{})
	if pub["EncryptFlag"] != false || pub["SessionType"] != "WebUI" {
		t.Fatalf("Oem.Public 内容错误: %v", pub)
	}
	if tag, _ := pub["LoginTag"].(float64); tag == 0 {
		t.Fatalf("LoginTag 未生成: %v", pub)
	}

	// 2) 读网卡
	st, err := c.ReadIface()
	if err != nil {
		t.Fatalf("读取网卡失败: %v", err)
	}
	if st.Path != "/redfish/v1/Managers/1/EthernetInterfaces/eth0" {
		t.Fatalf("资源路径探测错误: %s", st.Path)
	}
	if st.ETag != mock.etag {
		t.Fatalf("ETag 未取到: %q", st.ETag)
	}
	if st.IPv4.Address != "192.168.10.10" || st.IPv4.Gateway != "192.168.10.1" {
		t.Fatalf("当前配置解析错误: %+v", st.IPv4)
	}
	if mock.seenAuthHeader != c.token || mock.seenXSRFHeader != c.token {
		t.Fatalf("令牌未随请求下发: X-Auth-Token=%q X-XSRF-TOKEN=%q",
			mock.seenAuthHeader, mock.seenXSRFHeader)
	}

	// 3) 改 IP（与抓包同一组数据）
	if err := c.ApplyIPv4(st, "192.168.131.182", "255.255.255.0", "192.168.131.254"); err != nil {
		t.Fatalf("下发配置失败: %v", err)
	}

	arr, ok := mock.patchBody["IPv4Addresses"].([]interface{})
	if !ok || len(arr) != 1 {
		t.Fatalf("PATCH 报文结构错误: %v", mock.patchBody)
	}
	item := arr[0].(map[string]interface{})
	want := map[string]string{
		"AddressOrigin": "Static",
		"Address":       "192.168.131.182",
		"SubnetMask":    "255.255.255.0",
		"Gateway":       "192.168.131.254",
	}
	for k, v := range want {
		if item[k] != v {
			t.Errorf("PATCH 字段 %s = %v，期望 %s", k, item[k], v)
		}
	}
	if len(item) != len(want) {
		t.Errorf("PATCH 字段数量异常，可能多发了字段: %v", item)
	}
	if mock.ifMatchSeen != mock.etag {
		t.Errorf("If-Match 头错误: %q，期望 %q", mock.ifMatchSeen, mock.etag)
	}

	// 4) 登出
	c.Logout()
	if !mock.sessionDeleted {
		t.Error("登出未发出 DELETE 请求")
	}
	if c.token != "" {
		t.Error("登出后本地令牌未清空")
	}
}

// 老固件不接受 Oem 参数时，应自动降级到简化登录体。
func TestLoginFallsBackWhenOemRejected(t *testing.T) {
	mock := &mockBMC{t: t, rejectOemLogin: true}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	c := newTestClient(t, srv.URL, "sangfor", "S#AN$6fo81r")
	if err := c.Login(); err != nil {
		t.Fatalf("降级登录失败: %v", err)
	}
	if len(mock.loginBodies) != 2 {
		t.Fatalf("期望尝试 2 次登录，实际 %d 次", len(mock.loginBodies))
	}
	if _, hasOem := mock.loginBodies[0]["Oem"]; !hasOem {
		t.Error("第一次登录应带 Oem 参数")
	}
	if _, hasOem := mock.loginBodies[1]["Oem"]; hasOem {
		t.Error("第二次登录应去掉 Oem 参数")
	}
}

// 401 属于账号密码问题，不应继续无意义重试。
func TestLoginStopsOnUnauthorized(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Invalid username or password"}}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, "sangfor", "wrong")
	err := c.Login()
	if err == nil {
		t.Fatal("凭据错误时应返回失败")
	}
	if calls != 1 {
		t.Errorf("401 后不应重试，实际请求 %d 次", calls)
	}
	if !strings.Contains(err.Error(), "Invalid username or password") {
		t.Errorf("错误信息未带出服务端提示: %v", err)
	}
}

// ETag 失效（412）时应重新读取并重试一次。
func TestApplyRetriesOn412(t *testing.T) {
	mock := &mockBMC{t: t, etag: `"OLD"`, failFirstPatch: true}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	c := newTestClient(t, srv.URL, "sangfor", "S#AN$6fo81r")
	if err := c.Login(); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	st, err := c.ReadIface()
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if err := c.ApplyIPv4(st, "192.168.131.182", "255.255.255.0", "192.168.131.254"); err != nil {
		t.Fatalf("412 后应自动重试成功，实际: %v", err)
	}
	if mock.patchCount != 2 {
		t.Errorf("期望 PATCH 两次，实际 %d 次", mock.patchCount)
	}
}

// 网络不可达时错误信息应可读。
func TestUnreachableHostMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // 立刻关闭，制造连接拒绝

	c := newTestClient(t, url, "sangfor", "S#AN$6fo81r")
	err := c.Login()
	if err == nil {
		t.Fatal("不可达时应返回错误")
	}
	if !strings.Contains(err.Error(), "连接被拒绝") && !strings.Contains(err.Error(), "连接") {
		t.Errorf("错误信息不够友好: %v", err)
	}
}

// 部分固件只认某一种认证头形式：客户端应能自动切换并完成读取。
func TestAuthHeaderFallback(t *testing.T) {
	const token = "bZGSiwnBka7zO6mdtDSiA7OflBT1YkEw"

	// 只接受「仅带 X-XSRF-TOKEN」的请求，其它一律 401
	requireOnlyXSRF := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("X-XSRF-TOKEN") == token && r.Header.Get("X-Auth-Token") == "" {
			return true
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"unauthorized"}}`))
		return false
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/SessionService/Sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id":"s1","Oem":{"Public":{"X-Auth-Token":"` + token + `"}}}`))
	})
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, r *http.Request) {
		if !requireOnlyXSRF(w, r) {
			return
		}
		_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/1"}]}`))
	})
	mux.HandleFunc("/redfish/v1/Managers/1/EthernetInterfaces", func(w http.ResponseWriter, r *http.Request) {
		if !requireOnlyXSRF(w, r) {
			return
		}
		_, _ = w.Write([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces/eth0"}]}`))
	})
	mux.HandleFunc("/redfish/v1/Managers/1/EthernetInterfaces/eth0", func(w http.ResponseWriter, r *http.Request) {
		if !requireOnlyXSRF(w, r) {
			return
		}
		w.Header().Set("ETag", `"E1"`)
		_, _ = w.Write([]byte(eth0JSON))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "sangfor", "S#AN$6fo81r")
	if err := c.Login(); err != nil {
		t.Fatalf("登录失败: %v", err)
	}

	st, err := c.ReadIface()
	if err != nil {
		t.Fatalf("应通过自动切换认证头完成读取，实际失败: %v", err)
	}
	if st.IPv4.Address != "192.168.10.10" {
		t.Errorf("配置解析错误: %+v", st.IPv4)
	}
	if c.authMode != 2 {
		t.Errorf("期望最终落在「仅 X-XSRF-TOKEN」模式(2)，实际 %d", c.authMode)
	}
}

/* --------------------------- 取消（「停止」按钮） --------------------------- */

// 「黑洞」服务端：接受 TCP 连接但永不回包，用来模拟设备卡死/网络不通。
func blackHoleServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	conns := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- c // 抓着不放，也不写任何响应
		}
	}()
	t.Cleanup(func() {
		close(conns)
		for c := range conns {
			_ = c.Close()
		}
	})

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("地址解析失败: %v", err)
	}
	return port
}

// 取消上下文后，在途请求必须立刻返回 —— 这是「停止」按钮的核心保证。
func TestCancelAbortsInFlightRequest(t *testing.T) {
	port := blackHoleServer(t)

	c := NewClient("127.0.0.1", port, "sangfor", "x", func(string, ...interface{}) {})
	ctx, cancel := context.WithCancel(context.Background())
	c.WithContext(ctx)

	done := make(chan error, 1)
	go func() { done <- c.Login() }()

	time.Sleep(300 * time.Millisecond) // 让它先卡在连接/TLS 握手上
	start := time.Now()
	cancel()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("取消后应返回错误")
		}
		if !IsCanceled(err) {
			t.Errorf("应被识别为「已停止」，实际错误: %v", err)
		}
		if elapsed > 2*time.Second {
			t.Errorf("取消后返回太慢（%v），停止按钮会显得无反应", elapsed)
		}
		t.Logf("✓ 取消后 %v 内返回：%v", elapsed, err)
	case <-time.After(5 * time.Second):
		t.Fatal("取消后请求仍未返回，「停止」功能失效")
	}
}

// 未取消时应走正常超时，而不是被误判成取消。
func TestTimeoutIsNotTreatedAsCancel(t *testing.T) {
	port := blackHoleServer(t)

	// 把超时压到很小，避免测试等太久
	old := TLSHandshakeTimeout
	TLSHandshakeTimeout = 600 * time.Millisecond
	defer func() { TLSHandshakeTimeout = old }()

	c := NewClient("127.0.0.1", port, "sangfor", "x", func(string, ...interface{}) {})
	err := c.Login()
	if err == nil {
		t.Fatal("黑洞服务端应当超时")
	}
	if IsCanceled(err) {
		t.Errorf("超时被误判为用户取消：%v", err)
	}
	t.Logf("✓ 超时未被误判为取消：%v", err)
}

/* ------------------------------ 校验函数 ------------------------------ */

func TestParseIPv4AndMask(t *testing.T) {
	good := []string{"192.168.10.10", "10.0.0.254", " 172.16.1.1 "}
	for _, s := range good {
		if _, err := ParseIPv4(s); err != nil {
			t.Errorf("合法 IP 被判为非法: %s (%v)", s, err)
		}
	}
	bad := []string{"", "192.168.10", "192.168.10.256", "abc", "fe80::1"}
	for _, s := range bad {
		if _, err := ParseIPv4(s); err == nil {
			t.Errorf("非法 IP 未拦下: %s", s)
		}
	}

	if _, err := ParseMask("255.255.255.0"); err != nil {
		t.Errorf("合法掩码被拒: %v", err)
	}
	if _, err := ParseMask("255.0.255.0"); err == nil {
		t.Error("非连续掩码应被拒绝")
	}
	if _, err := ParseMask("0.0.0.0"); err == nil {
		t.Error("全零掩码应被拒绝")
	}
}

func TestSameSubnet(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("192.168.10.0/24")
	_ = ipnet

	ip, _ := ParseIPv4("192.168.10.10")
	gw, _ := ParseIPv4("192.168.10.1")
	mask, _ := ParseMask("255.255.255.0")
	if !SameSubnet(ip, gw, mask) {
		t.Error("同网段判定错误")
	}

	otherGW, _ := ParseIPv4("192.168.131.254")
	if SameSubnet(ip, otherGW, mask) {
		t.Error("跨网段应判为不同网段")
	}
}
