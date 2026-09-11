//go:build windows

package main

// main.go —— 深信服 BMC 管理口 IP 修改工具（原生 Windows GUI，基于 lxn/walk）
//
// 设计目标：日常只剩一件事 —— 填一个 IP。
// 连接信息有默认值；掩码/网关可点「读取当前配置」带出，之后按需手改。
//
// 两个 walk 布局陷阱（都已规避）：
//  1. LineEdit 的 MaxLength > 29 会被标记为 GreedyHorz，在 Grid 里会吃掉整行宽度，
//     把同排其它控件挤出窗口 —— 这里所有输入框都限制 MaxLength 并给出 Min/MaxSize。
//  2. walk 的尺寸单位是 96 DPI 逻辑像素，会按屏幕 DPI 放大。
//     高 DPI + 小屏时若写死尺寸，窗口会比屏幕还大 —— 这里按屏幕可用区自动收敛。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

const (
	appTitle = "深信服 BMC 管理口 IP 修改工具"
	appVer   = "v1.1.2"
)

// 出厂默认值，取自抓包环境。
const (
	defHost = "192.168.10.10"
	defPort = "443"
	defUser = "sangfor"
	defPass = "S#AN$6fo81r"
)

// 控件宽度（96 DPI 逻辑像素）。
const (
	wHost = 175
	wPort = 70
	wUser = 175
	wPass = 150
	wIP   = 140
	wMask = 122
	wGw   = 122

	winMinW  = 560
	winMinH  = 330
	winWantW = 700
	winWantH = 540
)

/* ------------------------------ 自适应窗口尺寸 ------------------------------ */

// fitWindow 按当前窗口的真实 DPI 与屏幕可用区收敛初始尺寸。
//
// walk 的一个坑：MainWindow 的 Size 走「物理像素」，
// 而 MinSize 与字体走「96 DPI 逻辑单位」。若把逻辑值直接当 Size 传进去，
// 高 DPI 小屏上内容会整体溢出窗口。
// 因此这里在窗口创建之后（此时 DPI 可查）用 SetSizePixels 下发物理像素。
func (a *App) fitWindow() {
	dpi := 96
	if d := a.mw.DPI(); d > 0 {
		dpi = d
	}
	sw := int(win.GetSystemMetrics(win.SM_CXSCREEN))
	sh := int(win.GetSystemMetrics(win.SM_CYSCREEN))

	// 先按逻辑单位与屏幕可用区取小
	w, h := winWantW, winWantH
	if sw > 0 && sh > 0 {
		if maxW := sw*96/dpi - 16; w > maxW {
			w = maxW
		}
		if maxH := sh*96/dpi - 60; h > maxH {
			h = maxH
		}
	}
	if w < winMinW {
		w = winMinW
	}
	if h < winMinH {
		h = winMinH
	}

	// 再换算成物理像素，并确保不超过屏幕
	dpiW, dpiH := w*dpi/96, h*dpi/96
	if sw > 0 && dpiW > sw {
		dpiW = sw
	}
	if sh > 0 && dpiH > sh {
		dpiH = sh
	}
	_ = a.mw.SetSizePixels(walk.Size{Width: dpiW, Height: dpiH})

	// 仅在确实因屏幕太小而压缩过窗口时提示一句，便于排查显示异常
	if w < winWantW || h < winWantH {
		a.logf("屏幕可用区较小，窗口已按屏幕自适应为 %d×%d 逻辑像素（屏幕 DPI %d）。", w, h, dpi)
	}
}

/* ------------------------------ 配置持久化 ------------------------------ */

type Config struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Remember bool   `json:"remember"`
}

// configPath 返回配置文件路径。
// os.UserConfigDir() 依赖 %AppData%，在某些精简环境（部分服务、被剥掉环境变量的进程）
// 下会失败；这里补一层兜底，避免"设置了却存不下来"这种静默失效。
func configPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		if up := os.Getenv("USERPROFILE"); up != "" {
			dir = filepath.Join(up, "AppData", "Roaming")
		} else if hd, err := os.UserHomeDir(); err == nil && hd != "" {
			dir = filepath.Join(hd, ".config")
		} else {
			return ""
		}
	}
	return filepath.Join(dir, "bmc-ip-tool", "config.json")
}

func loadConfig() Config {
	def := Config{Host: defHost, Port: defPort, User: defUser, Pass: defPass, Remember: true}
	p := configPath()
	if p == "" {
		return def
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return def
	}
	var c Config
	if json.Unmarshal(b, &c) != nil {
		return def
	}
	if strings.TrimSpace(c.Host) == "" {
		c.Host = def.Host
	}
	if strings.TrimSpace(c.Port) == "" {
		c.Port = def.Port
	}
	if strings.TrimSpace(c.User) == "" {
		c.User = def.User
	}
	if c.Pass == "" && c.Remember {
		c.Pass = def.Pass
	}
	return c
}

func saveConfig(c Config) {
	p := configPath()
	if p == "" {
		return
	}
	if !c.Remember {
		c.Pass = "" // 不勾选「记住」就不落盘密码
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(p, b, 0o600)
}

/* --------------------------------- 应用 --------------------------------- */

type App struct {
	mw *walk.MainWindow

	hostEdit, portEdit, userEdit, passEdit *walk.LineEdit
	showPass                               *walk.CheckBox
	remember                               *walk.CheckBox

	lblCur *walk.Label // 一行式当前配置摘要

	newIPEdit, maskEdit, gwEdit *walk.LineEdit

	readBtn, applyBtn, stopBtn *walk.PushButton
	logBox                     *walk.TextEdit

	// 运行中的「读取/修改」操作，供「停止」按钮取消
	opMu     sync.Mutex
	cancelOp context.CancelFunc
	stopping bool

	// 最近一次从设备读回的配置，用于同网段提示与「未变化」校验
	haveCur bool
	curIPv4 IPv4Conf
}

func main() {
	cfg := loadConfig()
	app := &App{}

	err := (MainWindow{
		AssignTo: &app.mw,
		Title:    appTitle + " " + appVer,
		MinSize:  Size{Width: winMinW, Height: winMinH},
		Font:     Font{Family: "Microsoft YaHei UI", PointSize: 9},
		Layout:   VBox{Spacing: 6},
		Children: []Widget{
			// ---------- ① 连接信息 ----------
			GroupBox{
				Title:  "① 连接信息",
				Layout: Grid{Columns: 4, Spacing: 6},
				Children: []Widget{
					Label{Text: "设备地址:"},
					LineEdit{
						AssignTo:  &app.hostEdit,
						Text:      cfg.Host,
						MaxLength: 29,
						MinSize:   Size{Width: wHost},
						MaxSize:   Size{Width: wHost},
						CueBanner: defHost,
					},
					Label{Text: "端口:"},
					// 外面套一层 HBox + HSpacer：否则同列的密码框较宽会把本列撑开，
					// 端口输入框会被拉得很长。
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							LineEdit{
								AssignTo:  &app.portEdit,
								Text:      cfg.Port,
								MaxLength: 5,
								MinSize:   Size{Width: wPort},
								MaxSize:   Size{Width: wPort},
							},
							HSpacer{},
						},
					},
					Label{Text: "用户名:"},
					LineEdit{
						AssignTo:  &app.userEdit,
						Text:      cfg.User,
						MaxLength: 29,
						MinSize:   Size{Width: wUser},
						MaxSize:   Size{Width: wUser},
					},
					Label{Text: "密码:"},
					Composite{
						Layout: HBox{MarginsZero: true, Spacing: 6},
						Children: []Widget{
							LineEdit{
								AssignTo:     &app.passEdit,
								Text:         cfg.Pass,
								MaxLength:    29,
								PasswordMode: true,
								MinSize:      Size{Width: wPass},
								MaxSize:      Size{Width: wPass},
							},
							CheckBox{
								AssignTo: &app.showPass,
								Text:     "显示",
								OnCheckedChanged: func() {
									app.passEdit.SetPasswordMode(!app.showPass.Checked())
								},
							},
							// 吸收多余宽度，避免密码框被拉长、把「显示」推远
							HSpacer{},
						},
					},

					Label{
						AssignTo:   &app.lblCur,
						ColumnSpan: 4,
						Text:       "当前配置：尚未读取（点右下角「读取当前配置」）",
						TextColor:  walk.RGB(96, 112, 136),
					},
				},
			},

			// ---------- ② 修改为 ----------
			GroupBox{
				Title:  "② 修改为（日常只需填第一个）",
				Layout: Grid{Columns: 6, Spacing: 6},
				Children: []Widget{
					Label{Text: "新 IP"},
					LineEdit{
						AssignTo:  &app.newIPEdit,
						MaxLength: 29,
						MinSize:   Size{Width: wIP},
						MaxSize:   Size{Width: wIP},
						CueBanner: "192.168.131.182",
					},
					Label{Text: "掩码"},
					LineEdit{
						AssignTo:  &app.maskEdit,
						MaxLength: 29,
						MinSize:   Size{Width: wMask},
						MaxSize:   Size{Width: wMask},
						CueBanner: "255.255.255.0",
					},
					Label{Text: "网关"},
					LineEdit{
						AssignTo:  &app.gwEdit,
						MaxLength: 29,
						MinSize:   Size{Width: wGw},
						MaxSize:   Size{Width: wGw},
						CueBanner: "192.168.131.254",
					},
				},
			},

			// ---------- 操作按钮 ----------
			Composite{
				Layout: HBox{MarginsZero: true, Spacing: 6},
				Children: []Widget{
					CheckBox{
						AssignTo: &app.remember,
						Text:     "记住填写内容",
						Checked:  cfg.Remember,
					},
					HSpacer{},
					PushButton{
						AssignTo:  &app.readBtn,
						Text:      "读取当前配置",
						MinSize:   Size{Width: 104, Height: 28},
						OnClicked: func() { app.doRead() },
					},
					PushButton{
						AssignTo:  &app.applyBtn,
						Text:      "修改 IP",
						MinSize:   Size{Width: 86, Height: 28},
						OnClicked: func() { app.doApply() },
					},
					PushButton{
						AssignTo:  &app.stopBtn,
						Text:      "停止",
						MinSize:   Size{Width: 56, Height: 28},
						OnClicked: func() { app.stopOp() },
					},
					PushButton{
						Text:      "清空日志",
						MinSize:   Size{Width: 70, Height: 28},
						OnClicked: func() { app.logBox.SetText("") },
					},
					PushButton{
						Text:      "退出",
						MinSize:   Size{Width: 54, Height: 28},
						OnClicked: func() { app.mw.Close() },
					},
				},
			},

			// ---------- 日志 ----------
			GroupBox{
				Title:         "运行日志",
				StretchFactor: 1,
				Layout:        VBox{},
				Children: []Widget{
					TextEdit{
						AssignTo:      &app.logBox,
						VScroll:       true,
						MinSize:       Size{Height: 36},
						StretchFactor: 1,
						Font:          Font{Family: "Consolas", PointSize: 9},
					},
				},
			},
		},
	}).Create()
	if err != nil {
		os.Exit(1)
	}

	_ = app.logBox.SetReadOnly(true)
	app.stopBtn.SetEnabled(false) // 只有操作在跑时才可点
	app.fitWindow()               // 按真实 DPI 与屏幕可用区收敛窗口尺寸
	app.logf("%s %s 已就绪。设备 %s:%s，用户 %s。", appTitle, appVer, cfg.Host, cfg.Port, cfg.User)
	app.logf("用法：先点「读取当前配置」→ 填新 IP（掩码/网关按需改）→ 点「修改 IP」。")
	app.logf("掩码与网关不做自动推断，请按网络规划填写。")
	app.logf("注意：修改成功后 BMC 立即换到新地址，当前会话会断开，需用新 IP 重新访问。")
	app.logf("网络不通时：建连最多等 %s 就会报错，期间可随时点「停止」中断。", DialTimeout)
	app.logf("提示：勾选「记住填写内容」会把密码明文写入 %s", configPath())

	app.mw.Run()
}

/* ------------------------------- 界面辅助 ------------------------------- */

// ui 把回调切到 UI 线程执行，窗口销毁后静默忽略。
func (a *App) ui(f func()) {
	defer func() { _ = recover() }()
	if a.mw == nil {
		return
	}
	a.mw.Synchronize(f)
}

func (a *App) logf(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	stamp := time.Now().Format("15:04:05")
	a.ui(func() {
		a.logBox.AppendText("[" + stamp + "] " + line + "\r\n")
		a.logBox.ScrollToCaret()
	})
}

func (a *App) setBusyUI(busy bool) {
	a.ui(func() {
		a.readBtn.SetEnabled(!busy)
		a.applyBtn.SetEnabled(!busy)
		a.stopBtn.SetEnabled(busy) // 只有操作在跑时才允许点停止
	})
}

/* ---------------------------- 可停止的操作 ---------------------------- */

// beginOp 开始一个可被「停止」中断的操作，返回其上下文。
func (a *App) beginOp() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	a.opMu.Lock()
	if a.cancelOp != nil { // 上一次的取消函数若还在，先释放
		a.cancelOp()
	}
	a.cancelOp = cancel
	a.stopping = false
	a.opMu.Unlock()

	a.setBusyUI(true)
	return ctx
}

// endOp 结束操作，释放取消函数并把界面恢复为可操作。
// 幂等：可以在弹窗之前和 defer 里各调一次。
func (a *App) endOp() {
	a.opMu.Lock()
	cancel := a.cancelOp
	a.cancelOp = nil
	a.opMu.Unlock()

	if cancel != nil {
		cancel()
	}
	a.setBusyUI(false)
}

// stopOp 由「停止」按钮触发：取消上下文，在途请求会立刻返回。
func (a *App) stopOp() {
	a.opMu.Lock()
	if a.cancelOp == nil {
		a.opMu.Unlock()
		return
	}
	a.stopping = true
	cancel := a.cancelOp
	a.opMu.Unlock()

	a.logf("⏹ 已请求停止，正在中断在途请求…")
	cancel()
}

// isStopping 判断当前是否处于「用户主动停止」状态。
func (a *App) isStopping() bool {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	return a.stopping
}

func (a *App) info(title, msg string) {
	// 先恢复界面再弹模态框，理由同 fail()
	a.endOp()
	a.ui(func() {
		walk.MsgBox(a.mw, title, msg,
			walk.MsgBoxOK|walk.MsgBoxIconInformation|walk.MsgBoxSetForeground)
	})
}

func (a *App) warn(title, msg string) {
	a.ui(func() {
		walk.MsgBox(a.mw, title, msg,
			walk.MsgBoxOK|walk.MsgBoxIconWarning|walk.MsgBoxSetForeground)
	})
}

// fail 记录错误并弹窗。
//
// 两个要点：
//  1. 先把本次操作收尾（endOp）再弹窗 —— 模态框会禁用主窗口，
//     若此时界面还停在「忙碌」状态，用户点不动任何按钮，会以为程序卡死只能重启。
//  2. 弹窗带 SetForeground，避免它藏到主窗口后面导致主窗口被禁用又够不着弹窗。
//
// 若本次失败源于用户点了「停止」，则只记日志、不弹错误框（那不是故障）。
func (a *App) fail(title string, err error) {
	stopped := a.isStopping() || IsCanceled(err)
	a.endOp()

	if stopped {
		a.logf("⏹ %s：已被用户停止", title)
		return
	}
	a.logf("✗ %s：%v", title, err)
	a.warn(title, err.Error())
}

func (a *App) readConn() (host, port, user, pass string, err error) {
	host = strings.TrimSpace(a.hostEdit.Text())
	port = strings.TrimSpace(a.portEdit.Text())
	user = strings.TrimSpace(a.userEdit.Text())
	pass = a.passEdit.Text()

	if host == "" {
		return "", "", "", "", fmt.Errorf("请填写设备地址（BMC 的 IP）")
	}
	if user == "" {
		return "", "", "", "", fmt.Errorf("请填写用户名")
	}
	if pass == "" {
		return "", "", "", "", fmt.Errorf("请填写密码")
	}
	if port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return "", "", "", "", fmt.Errorf("端口不合法：%s", port)
		}
	}
	saveConfig(Config{Host: host, Port: port, User: user, Pass: pass, Remember: a.remember.Checked()})
	return host, port, user, pass, nil
}

func (a *App) updateCurrent(st *IfaceState) {
	a.curIPv4 = st.IPv4
	a.haveCur = st.IPv4.Address != ""
	summary := fmt.Sprintf("当前配置：IP %s ｜ 掩码 %s ｜ 网关 %s ｜ 管理口 %s",
		orDash(st.IPv4.Address), orDash(st.IPv4.SubnetMask), orDash(st.IPv4.Gateway), orDash(st.ID))
	a.ui(func() { a.lblCur.SetText(summary) })
}

/* ------------------------------- 读取配置 ------------------------------- */

func (a *App) doRead() {
	host, port, user, pass, err := a.readConn()
	if err != nil {
		a.warn("连接信息有误", err.Error())
		return
	}
	// 开始一段可被「停止」中断的操作
	ctx := a.beginOp()
	go func() {
		defer a.endOp()
		a.logf("──── 读取当前配置 ────")
		a.logf("目标 %s:%s，用户 %s（连接超时 %s，可随时点「停止」）",
			host, orDefault(port, "443"), user, DialTimeout)

		c := NewClient(host, port, user, pass, a.logf).WithContext(ctx)
		if err := c.Login(); err != nil {
			a.fail("登录失败", err)
			return
		}
		defer c.Logout()

		st, err := c.ReadIface()
		if err != nil {
			a.fail("读取失败", err)
			return
		}
		a.updateCurrent(st)

		if st.DHCPEnabled {
			a.logf("⚠ 该管理口当前是 DHCP 模式，改为静态地址前请确认不会与现网冲突。")
		}
		a.logf("当前：IP %s / 掩码 %s / 网关 %s",
			orDash(st.IPv4.Address), orDash(st.IPv4.SubnetMask), orDash(st.IPv4.Gateway))

		// 带出到输入框：掩码、网关沿用现有值，新 IP 给个起点
		cur := st.IPv4
		a.ui(func() {
			if cur.Address != "" && strings.TrimSpace(a.newIPEdit.Text()) == "" {
				a.newIPEdit.SetText(cur.Address)
			}
			if cur.SubnetMask != "" {
				a.maskEdit.SetText(cur.SubnetMask)
			}
			if cur.Gateway != "" {
				a.gwEdit.SetText(cur.Gateway)
			}
		})
		a.logf("✓ 读取完成，已带出掩码/网关，请填写要改成的新 IP。")
	}()
}

/* ------------------------------- 执行修改 ------------------------------- */

func (a *App) doApply() {
	host, port, user, pass, err := a.readConn()
	if err != nil {
		a.warn("连接信息有误", err.Error())
		return
	}

	newIPStr := strings.TrimSpace(a.newIPEdit.Text())
	maskStr := strings.TrimSpace(a.maskEdit.Text())
	gwStr := strings.TrimSpace(a.gwEdit.Text())

	if newIPStr == "" {
		a.warn("缺少参数", "请填写「新 IP」。")
		return
	}
	newIP, err := ParseIPv4(newIPStr)
	if err != nil {
		a.warn("IP 不合法", err.Error())
		return
	}
	if maskStr == "" {
		a.warn("缺少参数", "请填写「掩码」。可先点「读取当前配置」自动带出。")
		return
	}
	mask, err := ParseMask(maskStr)
	if err != nil {
		a.warn("掩码不合法", err.Error())
		return
	}
	if gwStr == "" {
		a.warn("缺少参数", "请填写「网关」。可先点「读取当前配置」自动带出。")
		return
	}
	gwIP, err := ParseIPv4(gwStr)
	if err != nil {
		a.warn("网关不合法", err.Error())
		return
	}

	// 网关不在新网段内，几乎必然是填错了，会把 BMC 锁在同网段之外
	note := ""
	if !SameSubnet(newIP, gwIP, mask) {
		note = fmt.Sprintf("\n\n⚠ 注意：新 IP %s 与网关 %s 不在同一网段（掩码 %s）。\n"+
			"若网关填错，BMC 将只能被同网段主机访问，请务必确认。", newIPStr, gwStr, maskStr)
	}
	if a.haveCur && a.curIPv4.Address == newIPStr {
		note += "\n\n⚠ 新 IP 与设备当前 IP 相同，本次修改不会产生变化。"
	}

	before := "（未知，建议先读取当前配置）"
	if a.haveCur {
		before = fmt.Sprintf("%s / %s / %s", a.curIPv4.Address, a.curIPv4.SubnetMask, a.curIPv4.Gateway)
	}
	confirm := fmt.Sprintf(
		"即将把 BMC 管理口改为：\n\n"+
			"      新 IP：%s\n"+
			"        掩码：%s\n"+
			"        网关：%s\n\n"+
			"设备地址：%s\n修改前：%s\n\n"+
			"⚠ 修改成功后 BMC 会立即切换到新地址，当前会话断开，\n"+
			"需要用新 IP 重新打开管理页面。\n"+
			"请确认新地址可用且不与现网冲突。%s",
		newIPStr, maskStr, gwStr, host, before, note)

	if walk.MsgBox(a.mw, "确认修改", confirm,
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning|walk.MsgBoxDefButton2) != walk.DlgCmdYes {
		a.logf("已取消本次修改。")
		return
	}

	ctx := a.beginOp()
	go func() {
		defer a.endOp()
		a.logf("──── 开始修改 ────")
		a.logf("目标 %s:%s，用户 %s（连接超时 %s，可随时点「停止」）",
			host, orDefault(port, "443"), user, DialTimeout)

		c := NewClient(host, port, user, pass, a.logf).WithContext(ctx)
		if err := c.Login(); err != nil {
			a.fail("登录失败", err)
			return
		}
		defer c.Logout()

		// 先读一次：拿最新 ETag，同时确认修改前的真实状态
		st, err := c.ReadIface()
		if err != nil {
			a.fail("修改前读取配置失败", err)
			return
		}
		a.updateCurrent(st)
		a.logf("修改前：IP %s / 掩码 %s / 网关 %s",
			orDash(st.IPv4.Address), orDash(st.IPv4.SubnetMask), orDash(st.IPv4.Gateway))

		if st.IPv4.Address == newIPStr && st.IPv4.SubnetMask == maskStr && st.IPv4.Gateway == gwStr {
			a.logf("目标配置与当前完全一致，本次不下发。")
			a.info("无需修改", "新配置与设备当前配置完全一致，已跳过。")
			return
		}

		if err := c.ApplyIPv4(st, newIPStr, maskStr, gwStr); err != nil {
			if a.isStopping() || IsCanceled(err) {
				// 取消发生在「可能已下发」的时刻，无法确定设备是否收到，必须如实提示
				a.logf("⏹ 已停止。注意：下发请求可能已经到达设备，请用新地址 https://%s 或原地址核实后再操作。", newIPStr)
				return
			}
			a.fail("修改失败", err)
			return
		}

		// 下发后设备可能立即换地址，回读失败属正常现象
		time.Sleep(600 * time.Millisecond)
		if a.isStopping() || ctx.Err() != nil {
			a.logf("⏹ 已停止，跳过回读校验。")
			a.logf("管理口已下发为：%s / %s / 网关 %s —— 请用 https://%s 确认。",
				newIPStr, maskStr, gwStr, newIPStr)
			return
		}
		if st2, err := c.ReadIface(); err == nil {
			if st2.IPv4.Address == newIPStr {
				a.logf("✓ 回读校验通过：IP %s / 掩码 %s / 网关 %s",
					st2.IPv4.Address, st2.IPv4.SubnetMask, st2.IPv4.Gateway)
			} else {
				a.logf("回读结果仍为 %s，设备可能稍后才切换，请重连后确认。", orDash(st2.IPv4.Address))
			}
		} else {
			a.logf("回读失败（%v）—— 设备应已切到新地址，属正常现象。", err)
		}

		a.logf("──── 修改完成 ────")
		a.logf("请用新地址访问：https://%s", newIPStr)

		// 趁上下文还有效先把会话释放掉，再恢复界面、弹结果框
		c.Logout()
		a.endOp()

		newURL := "https://" + newIPStr
		a.ui(func() {
			r := walk.MsgBox(a.mw, "修改成功",
				fmt.Sprintf("管理口 IP 已修改为：\n\n    %s\n\n掩码：%s    网关：%s\n\n"+
					"请断开后使用新地址访问 BMC：\n%s\n\n是否现在用浏览器打开新地址？",
					newIPStr, maskStr, gwStr, newURL),
				walk.MsgBoxYesNo|walk.MsgBoxIconInformation|walk.MsgBoxSetForeground)
			if r == walk.DlgCmdYes {
				if err := exec.Command("cmd", "/c", "start", "", newURL).Start(); err != nil {
					a.logf("打开浏览器失败：%v", err)
				}
			}
		})
	}()
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}
