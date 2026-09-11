package main

// e2e_test.go —— 端到端联调：用真实客户端（redfish.go）打真实的模拟服务端（mockbmc）。
//
// 与 redfish_test.go 的区别：那边用 httptest（纯 HTTP、自造响应），
// 这边起的是真正的 HTTPS 服务 + 自签证书，走完 TCP → TLS → HTTP 整条链路，
// 与真机环境一致。所以「这里通过」才真正说明能对上真机。

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"bmc-iptool/mockbmc"
)

// startMock 起一个模拟 BMC，测试结束自动关闭。
func startMock(t *testing.T, opts mockbmc.Options) *mockbmc.Server {
	t.Helper()
	opts.Listen = "127.0.0.1:0" // 交给系统分配端口，避免测试间端口冲突
	opts.HTTPDash = ""
	opts.Logf = func(format string, args ...interface{}) { t.Logf("  [mock] "+format, args...) }
	srv, err := mockbmc.Start(opts)
	if err != nil {
		t.Fatalf("启动模拟端失败: %v", err)
	}
	t.Cleanup(srv.Stop)
	return srv
}

// clientFor 造一个指向模拟端的客户端（直接改 base，走真实 https）。
func clientFor(t *testing.T, srv *mockbmc.Server) *Client {
	t.Helper()
	c := NewClient("127.0.0.1", "", "sangfor", "S#AN$6fo81r",
		func(format string, args ...interface{}) { t.Logf("  [cli] "+format, args...) })
	c.base = srv.URL()
	return c
}

/* ------------------------------ 主流程 ------------------------------ */

// 完整跑一遍：登录 → 读取 → 改 IP → 回读校验 → 登出。
func TestE2E_ChangeIPAgainstMock(t *testing.T) {
	srv := startMock(t, mockbmc.Options{
		User: "sangfor", Pass: "S#AN$6fo81r",
		IP: "192.168.10.10", Mask: "255.255.255.0", GW: "192.168.10.1",
		RequireLoginOem: true, // 登录体必须与抓包一致
		RequireIfMatch:  true, // 必须带正确 ETag
	})

	c := clientFor(t, srv)

	// 1) 登录：模拟端会严格核对 Oem.Public{EncryptFlag,LoginTag,SessionType}
	if err := c.Login(); err != nil {
		t.Fatalf("登录失败（登录体与抓包不符会被模拟端拒绝）: %v", err)
	}
	defer c.Logout()

	// 2) 读取当前配置
	st, err := c.ReadIface()
	if err != nil {
		t.Fatalf("读取网卡配置失败: %v", err)
	}
	if st.IPv4.Address != "192.168.10.10" || st.IPv4.SubnetMask != "255.255.255.0" || st.IPv4.Gateway != "192.168.10.1" {
		t.Fatalf("初始配置读取错误: %+v", st.IPv4)
	}
	if st.ETag == "" {
		t.Fatal("未取到 ETag")
	}

	// 3) 改成抓包里那次操作的目标地址
	if err := c.ApplyIPv4(st, "192.168.131.182", "255.255.255.0", "192.168.131.254"); err != nil {
		t.Fatalf("下发配置失败: %v", err)
	}

	// 4) 模拟端应真的把状态改了
	ip, mask, gw, newEtag, _ := srv.State()
	if ip != "192.168.131.182" || mask != "255.255.255.0" || gw != "192.168.131.254" {
		t.Fatalf("模拟端状态未更新: %s/%s gw %s", ip, mask, gw)
	}
	if newEtag == st.ETag {
		t.Error("修改后 ETag 应变更，否则乐观锁形同虚设")
	}

	// 5) 回读校验（模拟端不像真机那样立刻切走地址，所以这里应当成功）
	st2, err := c.ReadIface()
	if err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if st2.IPv4.Address != "192.168.131.182" {
		t.Fatalf("回读地址不对: %s", st2.IPv4.Address)
	}
	t.Logf("✓ 完整流程通过：%s → %s", st.IPv4.Address, st2.IPv4.Address)
}

/* ---------------------------- 故障分支验证 ---------------------------- */

// 模拟端只接受「仅带 X-XSRF-TOKEN」的请求 → 客户端的认证头降级应生效。
func TestE2E_AuthHeaderFallback(t *testing.T) {
	srv := startMock(t, mockbmc.Options{
		User: "sangfor", Pass: "S#AN$6fo81r",
		RequireLoginOem:     true,
		RequireIfMatch:      true,
		AuthMode:            mockbmc.AuthXSRF, // 只认 X-XSRF-TOKEN
		StrictOneAuthHeader: true,             // 且不允许同时带两种
	})

	c := clientFor(t, srv)
	if err := c.Login(); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if _, err := c.ReadIface(); err != nil {
		t.Fatalf("认证头降级后仍读取失败: %v", err)
	}
	if c.authMode != 2 {
		t.Fatalf("期望最终收敛到「仅 X-XSRF-TOKEN」，实际 mode=%d（%s）", c.authMode, authModeName(c.authMode))
	}
	t.Log("✓ 客户端自动从「两种都带」降级到「仅 X-XSRF-TOKEN」并成功")
}

// 模拟端首次 PATCH 返回 412 → 客户端应重取 ETag 后重试成功。
func TestE2E_ETagRetryOn412(t *testing.T) {
	srv := startMock(t, mockbmc.Options{
		User: "sangfor", Pass: "S#AN$6fo81r",
		RequireLoginOem: true, RequireIfMatch: true,
		FailFirstPatch: true,
	})

	c := clientFor(t, srv)
	if err := c.Login(); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	defer c.Logout()

	st, err := c.ReadIface()
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if err := c.ApplyIPv4(st, "10.10.10.10", "255.255.255.0", "10.10.10.1"); err != nil {
		t.Fatalf("412 后应自动重试成功，实际失败: %v", err)
	}

	ip, _, _, _, _ := srv.State()
	if ip != "10.10.10.10" {
		t.Fatalf("重试后配置未生效: %s", ip)
	}
	t.Log("✓ 首次 412 后自动重取 ETag 并重试成功")
}

// 模拟老固件不接受 Oem 参数 → 客户端应降级到简化登录体。
func TestE2E_LoginBodyFallback(t *testing.T) {
	srv := startMock(t, mockbmc.Options{
		User: "sangfor", Pass: "S#AN$6fo81r",
		RejectOemLogin: true, // 带了 Oem 就拒，模拟老固件
		RequireIfMatch: true,
	})

	c := clientFor(t, srv)
	if err := c.Login(); err != nil {
		t.Fatalf("登录体降级后仍失败: %v", err)
	}
	if _, err := c.ReadIface(); err != nil {
		t.Fatalf("降级登录后读取失败: %v", err)
	}
	t.Log("✓ 首次登录被拒后自动降级登录体并成功")
}

// 设备在 PATCH 后立刻切走地址：客户端应能体面收场，不 panic、不挂死。
func TestE2E_DropAfterPatchIsHandledGracefully(t *testing.T) {
	srv := startMock(t, mockbmc.Options{
		User: "sangfor", Pass: "S#AN$6fo81r",
		RequireLoginOem: true, RequireIfMatch: true,
		DropAfterPatch: true,
	})

	c := clientFor(t, srv)
	if err := c.Login(); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	st, err := c.ReadIface()
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}

	if err := c.ApplyIPv4(st, "172.16.5.5", "255.255.255.0", "172.16.5.1"); err != nil {
		t.Fatalf("PATCH 本身应当成功: %v", err)
	}

	// 之后的回读必然失败（连接被掐断），关键是不能卡住、不能 panic
	done := make(chan error, 1)
	go func() {
		_, err := c.ReadIface()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("地址切走后回读不应成功（除非模拟端没生效）")
		}
		t.Logf("✓ 地址切走后回读如期失败且快速返回: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("回读卡死超过 10 秒，说明客户端对连接中断处理有问题")
	}
}

/* ------------------------- 反向验证：模拟端确实在校验 ------------------------- */

// 证明模拟端不是「什么都回 200」的空壳：
// 少了 Oem 的登录体、缺 If-Match 的 PATCH，都必须被拒。
func TestE2E_MockActuallyRejectsBadRequests(t *testing.T) {
	srv := startMock(t, mockbmc.Options{
		User: "sangfor", Pass: "S#AN$6fo81r",
		RequireLoginOem: true, RequireIfMatch: true,
	})

	raw := func(method, path, body string, hdr map[string]string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, srv.URL()+path, rdr)
		if err != nil {
			t.Fatalf("构造请求失败: %v", err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		hc := &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("请求失败: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// 1) 简化登录体（无 Oem）→ 必须 400
	code, body := raw(http.MethodPost, "/redfish/v1/SessionService/Sessions",
		`{"UserName":"sangfor","Password":"S#AN$6fo81r"}`, nil)
	if code != http.StatusBadRequest {
		t.Errorf("缺少 Oem 的登录体应被拒 400，实际 %d %s", code, body)
	} else {
		t.Logf("✓ 无 Oem 的登录体被拒：%s", strings.TrimSpace(body))
	}

	// 2) 密码错误 → 401
	code, body = raw(http.MethodPost, "/redfish/v1/SessionService/Sessions",
		`{"UserName":"sangfor","Password":"wrong","Oem":{"Public":{"EncryptFlag":false,"LoginTag":123,"SessionType":"WebUI"}}}`,
		nil)
	if code != http.StatusUnauthorized {
		t.Errorf("错误密码应 401，实际 %d %s", code, body)
	} else {
		t.Logf("✓ 错误密码被拒 401")
	}

	// 3) 正常登录拿令牌
	code, body = raw(http.MethodPost, "/redfish/v1/SessionService/Sessions",
		`{"UserName":"sangfor","Password":"S#AN$6fo81r","Oem":{"Public":{"EncryptFlag":false,"LoginTag":1191758861,"SessionType":"WebUI"}}}`,
		nil)
	if code != http.StatusOK {
		t.Fatalf("正常登录应 200，实际 %d %s", code, body)
	}
	var lr loginResp
	if err := json.Unmarshal([]byte(body), &lr); err != nil {
		t.Fatalf("登录响应解析失败: %v", err)
	}
	token := lr.Oem.Public.XAuthToken
	if token == "" {
		t.Fatalf("登录响应里没有令牌: %s", body)
	}

	// 4) 不带认证头读取 → 401
	code, _ = raw(http.MethodGet, "/redfish/v1/Managers/1/EthernetInterfaces/eth0", "", nil)
	if code != http.StatusUnauthorized {
		t.Errorf("无认证头应 401，实际 %d", code)
	} else {
		t.Log("✓ 无认证头被拒 401")
	}

	good := map[string]string{"X-Auth-Token": token}

	// 5) 读取拿 ETag
	code, body = raw(http.MethodGet, "/redfish/v1/Managers/1/EthernetInterfaces/eth0", "", good)
	if code != http.StatusOK {
		t.Fatalf("带令牌读取应 200，实际 %d %s", code, body)
	}

	// 6) PATCH 不带 If-Match → 412
	code, body = raw(http.MethodPatch, "/redfish/v1/Managers/1/EthernetInterfaces/eth0",
		`{"IPv4Addresses":[{"AddressOrigin":"Static","Address":"10.1.1.1","SubnetMask":"255.255.255.0","Gateway":"10.1.1.254"}]}`,
		good)
	if code != http.StatusPreconditionFailed {
		t.Errorf("缺 If-Match 应 412，实际 %d %s", code, body)
	} else {
		t.Log("✓ 缺 If-Match 被拒 412")
	}

	// 7) PATCH 带错误 If-Match → 412
	code, _ = raw(http.MethodPatch, "/redfish/v1/Managers/1/EthernetInterfaces/eth0",
		`{"IPv4Addresses":[{"AddressOrigin":"Static","Address":"10.1.1.1","SubnetMask":"255.255.255.0","Gateway":"10.1.1.254"}]}`,
		map[string]string{"X-Auth-Token": token, "If-Match": `"stale-etag"`})
	if code != http.StatusPreconditionFailed {
		t.Errorf("错误 If-Match 应 412，实际 %d", code)
	} else {
		t.Log("✓ 错误 If-Match 被拒 412")
	}

	// 8) PATCH 地址非法 → 400
	code, body = raw(http.MethodPatch, "/redfish/v1/Managers/1/EthernetInterfaces/eth0",
		`{"IPv4Addresses":[{"AddressOrigin":"Static","Address":"999.1.1.1","SubnetMask":"255.255.255.0","Gateway":"10.1.1.254"}]}`,
		map[string]string{"X-Auth-Token": token, "If-Match": currentETag(t, srv)})
	if code != http.StatusBadRequest {
		t.Errorf("非法地址应 400，实际 %d %s", code, body)
	} else {
		t.Logf("✓ 非法地址被拒 400：%s", strings.TrimSpace(body))
	}

	// 9) PATCH 掩码非法 → 400
	code, body = raw(http.MethodPatch, "/redfish/v1/Managers/1/EthernetInterfaces/eth0",
		`{"IPv4Addresses":[{"AddressOrigin":"Static","Address":"10.1.1.1","SubnetMask":"255.0.255.0","Gateway":"10.1.1.254"}]}`,
		map[string]string{"X-Auth-Token": token, "If-Match": currentETag(t, srv)})
	if code != http.StatusBadRequest {
		t.Errorf("非法掩码应 400，实际 %d %s", code, body)
	} else {
		t.Logf("✓ 非连续掩码被拒 400：%s", strings.TrimSpace(body))
	}

	// 10) 一切正确 → 200，且状态真的变了
	code, body = raw(http.MethodPatch, "/redfish/v1/Managers/1/EthernetInterfaces/eth0",
		`{"IPv4Addresses":[{"AddressOrigin":"Static","Address":"10.1.1.1","SubnetMask":"255.255.255.0","Gateway":"10.1.1.254"}]}`,
		map[string]string{"X-Auth-Token": token, "If-Match": currentETag(t, srv)})
	if code != http.StatusOK {
		t.Fatalf("合法 PATCH 应 200，实际 %d %s", code, body)
	}
	ip, _, _, _, _ := srv.State()
	if ip != "10.1.1.1" {
		t.Fatalf("合法 PATCH 后状态未更新: %s", ip)
	}
	t.Log("✓ 合法 PATCH 生效，模拟端状态已更新为 10.1.1.1")
}

func currentETag(t *testing.T, srv *mockbmc.Server) string {
	t.Helper()
	_, _, _, etag, _ := srv.State()
	if etag == "" {
		t.Fatal("模拟端没有 ETag")
	}
	return etag
}

/* --------------------------- 模拟端自身行为 --------------------------- */

// 面板与状态接口不经过鉴权，应可直接访问（方便浏览器查看）。
func TestE2E_MockDashboardAndState(t *testing.T) {
	srv := startMock(t, mockbmc.Options{User: "sangfor", Pass: "S#AN$6fo81r"})

	hc := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	resp, err := hc.Get(srv.URL() + "/")
	if err != nil {
		t.Fatalf("访问面板失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("面板应 200，实际 %d", resp.StatusCode)
	}
	for _, want := range []string{"模拟 BMC 状态面板", "管理口 IP", "192.168.10.10"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("面板缺少内容 %q", want)
		}
	}

	resp2, err := hc.Get(srv.URL() + "/mock/state")
	if err != nil {
		t.Fatalf("访问状态接口失败: %v", err)
	}
	defer resp2.Body.Close()
	var st struct {
		Current map[string]any `json:"current"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&st); err != nil {
		t.Fatalf("状态解析失败: %v", err)
	}
	if fmt.Sprint(st.Current["ip"]) != "192.168.10.10" {
		t.Errorf("状态接口返回的 IP 不对: %v", st.Current["ip"])
	}
	t.Log("✓ 面板与状态接口正常")
}
