//go:build windows

// 深信服 BMC 模拟服务端（测试用）
//
// 用途：在拿不到真实 BMC 时，用它代替真机来验证改 IP 工具是否真的能对上接口。
// 它按 192.168.10.10.har 抓包还原协议，并默认严格校验请求，任何一项不符就报错。
//
// 编译：go build -o BmcMock.exe ./bmcmock
// 运行：BmcMock.exe            （默认监听 https://127.0.0.1:8443）
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"bmc-iptool/mockbmc"
)

/* ------------------------------- 彩色输出 ------------------------------- */

const (
	cReset  = "\x1b[0m"
	cDim    = "\x1b[90m"
	cRed    = "\x1b[31m"
	cGreen  = "\x1b[32m"
	cYellow = "\x1b[33m"
	cBlue   = "\x1b[36m"
	cBold   = "\x1b[1m"
)

var useColor = true

// enableVT 打开 Windows 控制台的 ANSI 转义支持。
func enableVT() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getStdHandle := kernel32.NewProc("GetStdHandle")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	const stdOutputHandle = ^uintptr(10) // -11
	const enableVirtualTerminalProcessing = 0x0004

	h, _, _ := getStdHandle.Call(stdOutputHandle)
	if h == 0 || h == ^uintptr(0) {
		useColor = false
		return
	}
	var mode uint32
	if r, _, _ := getConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		useColor = false
		return
	}
	if r, _, _ := setConsoleMode.Call(h, uintptr(mode|enableVirtualTerminalProcessing)); r == 0 {
		useColor = false
	}
}

func col(c, s string) string {
	if !useColor {
		return s
	}
	return c + s + cReset
}

// printer 保证多 goroutine 输出不串行错乱。
type printer struct {
	mu sync.Mutex
}

func (p *printer) logf(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Printf("[%s] "+format+"\n", append([]interface{}{time.Now().Format("15:04:05")}, args...)...)
}

func (p *printer) raw(s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Println(s)
}

/* --------------------------------- 主流程 --------------------------------- */

func main() {
	enableVT()
	p := &printer{}

	var (
		listen  = flag.String("listen", "0.0.0.0:8443", "HTTPS 监听地址（被测工具连这个）")
		dash    = flag.String("http", "0.0.0.0:18080", "状态面板监听地址，设为空则不启用")
		user    = flag.String("user", "sangfor", "登录用户名")
		pass    = flag.String("pass", "S#AN$6fo81r", "登录密码")
		ip      = flag.String("ip", "192.168.10.10", "初始管理口 IP")
		mask    = flag.String("mask", "255.255.255.0", "初始子网掩码")
		gw      = flag.String("gw", "192.168.10.1", "初始默认网关")
		dhcp    = flag.Bool("dhcp", false, "初始为 DHCP 模式")
		latency = flag.Duration("latency", 0, "每个请求的人为延迟，例如 300ms")

		looseLogin = flag.Bool("loose-login", false, "关闭登录体严格校验（默认严格，按抓包校验 Oem.Public）")
		rejectOem  = flag.Bool("reject-oem-login", false, "模拟老固件：登录体带 Oem 就拒绝（验证客户端登录体降级）")
		looseETag  = flag.Bool("loose-etag", false, "关闭 If-Match 校验（默认要求带正确 ETag）")
		authMode   = flag.String("auth", mockbmc.AuthAny, "服务端认哪种认证头：any|x-auth-token|x-xsrf-token|bearer")
		strictOne  = flag.Bool("strict-one-auth", false, "只允许请求带一种认证头（用来逼出客户端的降级逻辑）")

		failLogin = flag.Bool("fail-first-login", false, "首次登录返回 400，验证客户端登录体降级")
		failPatch = flag.Bool("fail-first-patch", false, "首次 PATCH 返回 412，验证客户端重取 ETag 重试")
		dropPatch = flag.Bool("drop-after-patch", false, "PATCH 成功后掐断连接，模拟设备立即切走地址")
		noColor   = flag.Bool("no-color", false, "关闭彩色输出")
	)
	flag.Parse()

	if *noColor {
		useColor = false
	}

	srv, err := mockbmc.Start(mockbmc.Options{
		Listen:              *listen,
		HTTPDash:            *dash,
		User:                *user,
		Pass:                *pass,
		IP:                  *ip,
		Mask:                *mask,
		GW:                  *gw,
		DHCP:                *dhcp,
		Latency:             *latency,
		RequireLoginOem:     !*looseLogin && !*rejectOem,
		RejectOemLogin:      *rejectOem,
		RequireIfMatch:      !*looseETag,
		AuthMode:            *authMode,
		StrictOneAuthHeader: *strictOne,
		FailFirstLogin:      *failLogin,
		FailFirstPatch:      *failPatch,
		DropAfterPatch:      *dropPatch,
		Logf:                p.logf,
		Middleware: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/redfish/") {
					p.raw(col(cDim, fmt.Sprintf("[%s] ── %s %s   ← %s",
						time.Now().Format("15:04:05"), r.Method, r.URL.Path, r.RemoteAddr)))
				}
				next.ServeHTTP(w, r)
			})
		},
	})
	if err != nil {
		p.raw(col(cRed, "启动失败："+err.Error()))
		os.Exit(1)
	}
	defer srv.Stop()

	srv.OnChange(func(oldIP, newIP, mask, gw string) {
		p.raw(col(cBold+cGreen, fmt.Sprintf(
			"\n  ★★ 管理口已改为 %s/%s gw %s（原 %s）—— 真实设备此时会切走地址，原地址将失联\n",
			newIP, mask, gw, oldIP)))
	})

	printBanner(p, srv, *user, *pass, *ip, *mask, *gw, *authMode, *strictOne,
		!*looseLogin, *rejectOem, !*looseETag, *failLogin, *failPatch, *dropPatch, *latency)

	// 等待 Ctrl+C
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	p.raw("\n正在关闭模拟服务端…")
}

func printBanner(p *printer, srv *mockbmc.Server, user, pass, ip, mask, gw, authMode string,
	strictOne, strictLogin, rejectOem, strictETag, failLogin, failPatch, dropPatch bool, latency time.Duration) {

	line := strings.Repeat("=", 74)
	dashURL := srv.DashURL()
	if dashURL == "" {
		dashURL = "（已关闭）"
	}

	strict := func(b bool) string {
		if b {
			return col(cGreen, "严格")
		}
		return col(cYellow, "已放宽")
	}
	loginMode := strict(strictLogin)
	if rejectOem {
		loginMode = col(cYellow, "拒绝 Oem 参数（模拟老固件）")
	}

	p.raw("")
	p.raw(col(cBold, line))
	p.raw(col(cBold, "  深信服 BMC 模拟服务端（测试用）"))
	p.raw(col(cBold, line))
	p.raw(fmt.Sprintf("  Redfish 接口 ：%s", col(cBlue, srv.URL())))
	p.raw(fmt.Sprintf("  状态面板     ：%s", col(cBlue, dashURL)))
	p.raw(fmt.Sprintf("  登录账号     ：%s / %s", user, pass))
	p.raw(fmt.Sprintf("  初始管理口   ：%s / %s  gw %s", ip, mask, gw))
	p.raw("")
	p.raw(fmt.Sprintf("  校验模式     ：登录体=%s   If-Match=%s   认证头=%s%s",
		loginMode, strict(strictETag), col(cBlue, authMode),
		func() string {
			if strictOne {
				return "  " + col(cYellow, "仅允许单一认证头")
			}
			return ""
		}()))
	if latency > 0 {
		p.raw(fmt.Sprintf("  人为延迟     ：%s", latency))
	}
	inject := []string{}
	if failLogin {
		inject = append(inject, "首次登录返回 400")
	}
	if failPatch {
		inject = append(inject, "首次 PATCH 返回 412")
	}
	if dropPatch {
		inject = append(inject, "PATCH 后掐断连接")
	}
	if len(inject) > 0 {
		p.raw("  " + col(cYellow, "故障注入     ："+strings.Join(inject, "；")))
	}
	p.raw("")
	p.raw(col(cBold, "  在被测工具里这样填："))
	p.raw(fmt.Sprintf("      设备地址 ：%s", col(cBold, hostOnly(srv.Addr()))))
	p.raw(fmt.Sprintf("      端口     ：%s", col(cBold, portOnly(srv.Addr()))))
	p.raw(fmt.Sprintf("      用户名   ：%s", col(cBold, user)))
	p.raw(fmt.Sprintf("      密码     ：%s", col(cBold, pass)))
	p.raw("")
	p.raw(col(cDim, "  提示：工具点击「读取当前配置」后，会带出 192.168.10.10 —— 那是模拟的真机初始值，"))
	p.raw(col(cDim, "        改成任意 IP 点「修改 IP」，本窗口会打印实际收到的报文与校验结果。"))
	p.raw(col(cDim, "        浏览器打开状态面板可实时看管理口当前值。"))
	p.raw("")
	p.raw(col(cDim, "  按 Ctrl+C 退出"))
	p.raw(col(cBold, line))
	p.raw("")
}

func hostOnly(addr string) string {
	if h, _, err := split(addr); err == nil {
		return h
	}
	return addr
}

func portOnly(addr string) string {
	if _, p, err := split(addr); err == nil {
		return p
	}
	return ""
}

func split(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, "", fmt.Errorf("no port")
	}
	return addr[:i], addr[i+1:], nil
}
