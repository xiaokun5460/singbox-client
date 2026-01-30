package config

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// Errors
var (
	ErrSubscriptionNotFound = errors.New("subscription not found")
)

// File permissions
const (
	DirPerm  = 0755
	FilePerm = 0600 // Restrictive permissions for config files
)

type Config struct {
	Server       ServerConfig       `yaml:"server" json:"server"`
	SingBox      SingBoxConfig      `yaml:"singbox" json:"singbox"`
	DNS          DNSConfig          `yaml:"dns" json:"dns"`
	Proxy        ProxyConfig        `yaml:"proxy" json:"proxy"`
	Subscription SubscriptionConfig `yaml:"subscription" json:"subscription"`
}

type ServerConfig struct {
	Port int    `yaml:"port" json:"port"`
	Host string `yaml:"host" json:"host"`
}

type SingBoxConfig struct {
	BinaryPath string `yaml:"binary_path" json:"binary_path"`
	ConfigPath string `yaml:"config_path" json:"config_path"`
	LogLevel   string `yaml:"log_level" json:"log_level"`
}

type DNSConfig struct {
	DomesticServers []string `yaml:"domestic_servers" json:"domestic_servers"`
	ProxyServers    []string `yaml:"proxy_servers" json:"proxy_servers"`
}

type ProxyConfig struct {
	TUNAddress  string `yaml:"tun_address" json:"tun_address"`
	TUNStack    string `yaml:"tun_stack" json:"tun_stack"`
	AutoRoute   bool   `yaml:"auto_route" json:"auto_route"`
	StrictRoute bool   `yaml:"strict_route" json:"strict_route"`
}

type SubscriptionConfig struct {
	AutoUpdate     bool `yaml:"auto_update" json:"auto_update"`
	UpdateInterval int  `yaml:"update_interval" json:"update_interval"` // in minutes
}

type Subscription struct {
	ID        string `yaml:"id" json:"id"`
	Name      string `yaml:"name" json:"name"`
	URL       string `yaml:"url" json:"url"`
	UpdatedAt string `yaml:"updated_at" json:"updated_at"`
}

type AppState struct {
	Subscriptions []Subscription `yaml:"subscriptions" json:"subscriptions"`
	SelectedNode  string         `yaml:"selected_node" json:"selected_node"`
	ProxyMode     string         `yaml:"proxy_mode" json:"proxy_mode"` // global, rule, direct
	CustomRules   []CustomRule   `yaml:"custom_rules" json:"custom_rules"`
	BypassList    []BypassEntry  `yaml:"bypass_list" json:"bypass_list"` // 完全绕过 TUN 的地址
}

// BypassEntry 表示一个需要完全绕过 TUN 的地址
type BypassEntry struct {
	Address string `yaml:"address" json:"address"` // 域名或 IP
	Comment string `yaml:"comment" json:"comment"` // 备注
}

type CustomRule struct {
	Type     string `yaml:"type" json:"type"`         // domain, domain_suffix, ip_cidr, geosite, geoip
	Value    string `yaml:"value" json:"value"`
	Outbound string `yaml:"outbound" json:"outbound"` // proxy, direct, block
}

var (
	instance *Manager
	once     sync.Once
)

type Manager struct {
	mu       sync.RWMutex
	config   *Config
	state    *AppState
	dataDir  string
}

func GetManager() *Manager {
	once.Do(func() {
		instance = &Manager{}
	})
	return instance
}

func (m *Manager) Initialize(dataDir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dataDir = dataDir

	// Ensure data directories exist
	dirs := []string{
		dataDir,
		filepath.Join(dataDir, "subscriptions"),
		filepath.Join(dataDir, "singbox"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, DirPerm); err != nil {
			return err
		}
	}

	// Load or create default config
	if err := m.loadConfig(); err != nil {
		return err
	}

	// Load or create default state
	if err := m.loadState(); err != nil {
		return err
	}

	return nil
}

func (m *Manager) loadConfig() error {
	configPath := filepath.Join(m.dataDir, "config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			m.config = m.defaultConfig()
			return m.saveConfig()
		}
		return err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}
	m.config = &cfg
	return nil
}

func (m *Manager) loadState() error {
	statePath := filepath.Join(m.dataDir, "state.yaml")

	data, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			m.state = m.defaultState()
			return m.saveState()
		}
		return err
	}

	var state AppState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return err
	}
	m.state = &state
	return nil
}

func (m *Manager) defaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port: 3333,
			Host: "127.0.0.1",
		},
		SingBox: SingBoxConfig{
			BinaryPath: "/usr/local/bin/sing-box",
			ConfigPath: filepath.Join(m.dataDir, "singbox", "config.json"),
			LogLevel:   "info",
		},
		DNS: DNSConfig{
			DomesticServers: []string{"223.5.5.5", "119.29.29.29"},
			ProxyServers:    []string{"8.8.8.8", "1.1.1.1"},
		},
		Proxy: ProxyConfig{
			TUNAddress:  "172.19.0.1/30",
			TUNStack:    "system",
			AutoRoute:   true,
			StrictRoute: true,
		},
		Subscription: SubscriptionConfig{
			AutoUpdate:     true,
			UpdateInterval: 60, // 1 hour
		},
	}
}

func (m *Manager) defaultState() *AppState {
	return &AppState{
		Subscriptions: []Subscription{},
		SelectedNode:  "",
		ProxyMode:     "rule",
		CustomRules:   []CustomRule{},
		BypassList:    []BypassEntry{},
	}
}

func (m *Manager) saveConfig() error {
	configPath := filepath.Join(m.dataDir, "config.yaml")
	data, err := yaml.Marshal(m.config)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, FilePerm)
}

func (m *Manager) saveState() error {
	statePath := filepath.Join(m.dataDir, "state.yaml")
	data, err := yaml.Marshal(m.state)
	if err != nil {
		return err
	}
	return os.WriteFile(statePath, data, FilePerm)
}

func (m *Manager) GetConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *m.config
}

func (m *Manager) UpdateConfig(cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = &cfg
	return m.saveConfig()
}

func (m *Manager) GetState() AppState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *m.state
}

func (m *Manager) GetSubscriptions() []Subscription {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.Subscriptions
}

func (m *Manager) AddSubscription(sub Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.Subscriptions = append(m.state.Subscriptions, sub)
	return m.saveState()
}

func (m *Manager) UpdateSubscription(sub Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.state.Subscriptions {
		if s.ID == sub.ID {
			m.state.Subscriptions[i] = sub
			return m.saveState()
		}
	}
	return ErrSubscriptionNotFound
}

func (m *Manager) DeleteSubscription(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.state.Subscriptions {
		if s.ID == id {
			m.state.Subscriptions = append(m.state.Subscriptions[:i], m.state.Subscriptions[i+1:]...)
			return m.saveState()
		}
	}
	return ErrSubscriptionNotFound
}

func (m *Manager) SetSelectedNode(node string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.SelectedNode = node
	return m.saveState()
}

func (m *Manager) SetProxyMode(mode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.ProxyMode = mode
	return m.saveState()
}

func (m *Manager) GetCustomRules() []CustomRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.CustomRules
}

func (m *Manager) SetCustomRules(rules []CustomRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.CustomRules = rules
	return m.saveState()
}

func (m *Manager) GetDataDir() string {
	return m.dataDir
}

func (m *Manager) GetBypassList() []BypassEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.BypassList
}

func (m *Manager) SetBypassList(list []BypassEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.BypassList = list
	return m.saveState()
}
