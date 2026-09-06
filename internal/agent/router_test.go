package agent

import (
	"bytes"
	"testing"
)

func TestParseFingerprintASCII(t *testing.T) {
	fp, typ := parseFingerprint("SSH-2.0")
	if typ != MatchPrefix {
		t.Fatalf("want MatchPrefix, got %v", typ)
	}
	if !bytes.Equal(fp, []byte("SSH-2.0")) {
		t.Fatalf("ascii mismatch: %v", fp)
	}
}

func TestParseFingerprintHex(t *testing.T) {
	fp, typ := parseFingerprint("\x05\x01\x00")
	if typ != MatchPrefix {
		t.Fatalf("want MatchPrefix, got %v", typ)
	}
	if !bytes.Equal(fp, []byte{0x05, 0x01, 0x00}) {
		t.Fatalf("hex mismatch: %v", fp)
	}
}

func TestParseFingerprintMixed(t *testing.T) {
	fp, _ := parseFingerprint("GET\\x20/")
	if !bytes.Equal(fp, []byte("GET /")) {
		t.Fatalf("mixed mismatch: %q", fp)
	}
}

func TestParseFingerprintWildcard(t *testing.T) {
	for _, s := range []string{"*", ""} {
		fp, typ := parseFingerprint(s)
		if typ != MatchWildcard || fp != nil {
			t.Fatalf("%q: want wildcard nil, got %v/%v", s, typ, fp)
		}
	}
}

// 回归测试: 修复前 fingerprint_raw 字段被 yaml 忽略导致规则退化为通配符
func TestNewRouterFingerprintRawFallback(t *testing.T) {
	cfg := &Config{
		Rules: []RuleConfig{
			{Name: "socks5", FingerprintRaw: "\x05\x01\x00", Handler: "tcp_proxy", HandlerArgs: map[string]string{"target": "127.0.0.1:80"}, Priority: 2},
			{Name: "http", Fingerprint: "GET ", Handler: "tcp_proxy", HandlerArgs: map[string]string{"target": "127.0.0.1:80"}, Priority: 10},
		},
	}
	r := NewRouter(cfg)
	if len(r.rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(r.rules))
	}
	// 按 priority 排序
	if r.rules[0].Name != "socks5" || r.rules[1].Name != "http" {
		t.Fatalf("priority order wrong: %s, %s", r.rules[0].Name, r.rules[1].Name)
	}
	// fingerprint_raw 必须被解析为真实指纹, 而不是 nil(通配符)
	if r.rules[0].Fingerprint == nil {
		t.Fatal("fingerprint_raw not parsed: rule became wildcard")
	}
	if !bytes.Equal(r.rules[0].Fingerprint, []byte{0x05, 0x01, 0x00}) {
		t.Fatalf("fingerprint_raw mismatch: %v", r.rules[0].Fingerprint)
	}
}

// 回归测试: YAML 中 fingerprint_raw 覆盖 fingerprint
func TestNewRouterRawOverridesEmpty(t *testing.T) {
	cfg := &Config{
		Rules: []RuleConfig{
			{Name: "r1", Fingerprint: "", FingerprintRaw: "\xDE\xAD", Handler: "tcp_proxy", Priority: 1},
			{Name: "r2", Fingerprint: "ABC", FingerprintRaw: "ignored", Handler: "tcp_proxy", Priority: 2},
		},
	}
	r := NewRouter(cfg)
	if !bytes.Equal(r.rules[0].Fingerprint, []byte{0xDE, 0xAD}) {
		t.Fatalf("r1 raw fallback failed: %v", r.rules[0].Fingerprint)
	}
	if !bytes.Equal(r.rules[1].Fingerprint, []byte("ABC")) {
		t.Fatalf("r2 should prefer fingerprint: %v", r.rules[1].Fingerprint)
	}
}

// 回归: 配置字段拼错必须报错 (KnownFields), 不能静默忽略
func TestDecodeYAMLUnknownField(t *testing.T) {
	cfg := DefaultConfig()
	err := DecodeYAML([]byte("magic_key: k\nbad_field_name: 1\n"), cfg)
	if err == nil {
		t.Fatal("unknown field should fail with KnownFields")
	}
}

func TestDecodeYAMLKnownFieldsOK(t *testing.T) {
	cfg := DefaultConfig()
	in := "magic_key: k2\ncrypto:\n  enabled: false\ntimeouts:\n  peek_seconds: 5\nlisten:\n  iface: auto\n  watch_ports: [80, 8080]\n"
	if err := DecodeYAML([]byte(in), cfg); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.Crypto.Enabled {
		t.Fatal("crypto.enabled should be false")
	}
	if cfg.Timeouts.PeekSeconds != 5 {
		t.Fatalf("peek_seconds=%d", cfg.Timeouts.PeekSeconds)
	}
	if len(cfg.Listen.WatchPorts) != 2 {
		t.Fatalf("watch_ports=%v", cfg.Listen.WatchPorts)
	}
}
