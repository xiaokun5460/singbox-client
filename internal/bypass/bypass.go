package bypass

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"singbox-client/internal/config"
)

// Manager 管理绕过 TUN 的路由
type Manager struct {
	mu            sync.Mutex
	cfgMgr        *config.Manager
	gateway       string
	iface         string
	appliedRoutes map[string]bool // 已应用的路由
	stopChan      chan struct{}   // 停止自动刷新
	running       bool            // 自动刷新是否运行中
}

var (
	instance *Manager
	once     sync.Once
)

// GetManager 获取单例
func GetManager() *Manager {
	once.Do(func() {
		instance = &Manager{
			appliedRoutes: make(map[string]bool),
		}
	})
	return instance
}

// Initialize 初始化，检测默认网关和接口
func (m *Manager) Initialize(cfgMgr *config.Manager) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cfgMgr = cfgMgr

	if err := m.refreshDefaultRouteLocked(); err != nil {
		return fmt.Errorf("failed to detect default route: %w", err)
	}

	return nil
}

// detectDefaultRoute 检测默认网关和接口
func (m *Manager) detectDefaultRoute() (gateway, iface string, err error) {
	// 使用 ip route 获取默认路由
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", "", err
	}

	// 解析输出: default via 192.168.3.1 dev eno1 ...
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			gateway = fields[i+1]
		}
		if f == "dev" && i+1 < len(fields) {
			iface = fields[i+1]
		}
	}

	if gateway == "" || iface == "" {
		return "", "", fmt.Errorf("could not parse default route: %s", string(out))
	}

	return gateway, iface, nil
}

func (m *Manager) refreshDefaultRouteLocked() error {
	gateway, iface, err := m.detectDefaultRoute()
	if err != nil {
		return err
	}

	if err := m.validateInterfaceUsable(iface); err != nil {
		return err
	}

	m.gateway = gateway
	m.iface = iface
	return nil
}

func (m *Manager) validateInterfaceUsable(iface string) error {
	out, err := exec.Command("ip", "link", "show", "dev", iface).Output()
	if err != nil {
		return fmt.Errorf("failed to check interface %s: %w", iface, err)
	}

	status := string(out)
	if strings.Contains(status, "NO-CARRIER") || strings.Contains(status, "state DOWN") {
		return fmt.Errorf("default interface %s is down", iface)
	}

	return nil
}

// ApplyBypassRoutes 应用所有绕过路由
func (m *Manager) ApplyBypassRoutes() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.refreshDefaultRouteLocked(); err != nil {
		return fmt.Errorf("failed to refresh default route: %w", err)
	}

	bypassList := m.cfgMgr.GetBypassList()

	for _, entry := range bypassList {
		if err := m.addRouteForAddress(entry.Address); err != nil {
			// 记录错误但继续处理其他条目
			fmt.Printf("Warning: failed to add bypass route for %s: %v\n", entry.Address, err)
		}
	}

	return nil
}

// addRouteForAddress 为地址添加绕过路由
func (m *Manager) addRouteForAddress(address string) error {
	// 解析地址，可能是域名或 IP
	ips, err := m.resolveAddress(address)
	if err != nil {
		return err
	}

	for _, ip := range ips {
		if m.appliedRoutes[ip] {
			continue // 已经添加过
		}

		// 添加路由: ip route add <ip>/32 via <gateway> dev <iface>
		cmd := exec.Command("ip", "route", "add", ip+"/32", "via", m.gateway, "dev", m.iface)
		if out, err := cmd.CombinedOutput(); err != nil {
			msg := strings.TrimSpace(string(out))
			// 如果路由已存在，忽略错误
			if !strings.Contains(msg, "File exists") {
				if msg == "" {
					return fmt.Errorf("failed to add route for %s: %w", ip, err)
				}
				return fmt.Errorf("failed to add route for %s: %w: %s", ip, err, msg)
			}
		}

		m.appliedRoutes[ip] = true
	}

	return nil
}

// resolveAddress 解析地址为 IP 列表
func (m *Manager) resolveAddress(address string) ([]string, error) {
	// 检查是否已经是 IP
	if ip := net.ParseIP(address); ip != nil {
		return []string{address}, nil
	}

	// 检查是否是 CIDR
	if _, _, err := net.ParseCIDR(address); err == nil {
		// CIDR 格式，提取 IP 部分
		ip := strings.Split(address, "/")[0]
		return []string{ip}, nil
	}

	// 使用 DoH 解析域名，避免 sing-box fake-ip 干扰
	result, err := m.resolveViaDoH(address)
	if err != nil {
		// 回退到系统 DNS
		log.Printf("DoH resolve failed for %s, falling back to system DNS: %v", address, err)
		return m.resolveViaSystem(address)
	}

	return result, nil
}

// resolveViaDoH 通过 DNS over HTTPS 解析域名
func (m *Manager) resolveViaDoH(domain string) ([]string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://dns.google/resolve?name=%s&type=A", domain)

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var dohResp struct {
		Answer []struct {
			Data string `json:"data"`
			Type int    `json:"type"`
		} `json:"Answer"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&dohResp); err != nil {
		return nil, err
	}

	var result []string
	for _, ans := range dohResp.Answer {
		if ans.Type == 1 { // A record
			if ip := net.ParseIP(ans.Data); ip != nil && ip.To4() != nil {
				result = append(result, ans.Data)
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no IPv4 address found for %s", domain)
	}

	return result, nil
}

// resolveViaSystem 通过系统 DNS 解析
func (m *Manager) resolveViaSystem(address string) ([]string, error) {
	ips, err := net.LookupIP(address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", address, err)
	}

	var result []string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			result = append(result, ipv4.String())
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no IPv4 address found for %s", address)
	}

	return result, nil
}

// RemoveBypassRoutes 移除所有绕过路由
func (m *Manager) RemoveBypassRoutes() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for ip := range m.appliedRoutes {
		cmd := exec.Command("ip", "route", "del", ip+"/32")
		cmd.Run() // 忽略错误
	}

	m.appliedRoutes = make(map[string]bool)
	return nil
}

// AddBypassEntry 添加绕过条目并立即应用
func (m *Manager) AddBypassEntry(address, comment string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 添加到配置
	list := m.cfgMgr.GetBypassList()

	// 检查是否已存在
	for _, entry := range list {
		if entry.Address == address {
			return fmt.Errorf("address %s already in bypass list", address)
		}
	}

	list = append(list, config.BypassEntry{
		Address: address,
		Comment: comment,
	})

	if err := m.cfgMgr.SetBypassList(list); err != nil {
		return err
	}

	// 立即应用路由
	return m.addRouteForAddress(address)
}

// RemoveBypassEntry 移除绕过条目
func (m *Manager) RemoveBypassEntry(address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.cfgMgr.GetBypassList()

	found := false
	newList := make([]config.BypassEntry, 0, len(list))
	for _, entry := range list {
		if entry.Address == address {
			found = true
			continue
		}
		newList = append(newList, entry)
	}

	if !found {
		return fmt.Errorf("address %s not in bypass list", address)
	}

	if err := m.cfgMgr.SetBypassList(newList); err != nil {
		return err
	}

	// 移除路由
	ips, _ := m.resolveAddress(address)
	for _, ip := range ips {
		if m.appliedRoutes[ip] {
			exec.Command("ip", "route", "del", ip+"/32").Run()
			delete(m.appliedRoutes, ip)
		}
	}

	return nil
}

// GetBypassList 获取绕过列表
func (m *Manager) GetBypassList() []config.BypassEntry {
	return m.cfgMgr.GetBypassList()
}

// GetGatewayInfo 获取网关信息
func (m *Manager) GetGatewayInfo() (gateway, iface string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gateway, m.iface
}

// RefreshRoutes 刷新路由（域名 IP 可能变化）
func (m *Manager) RefreshRoutes() error {
	// 先清除旧路由
	m.RemoveBypassRoutes()
	// 重新应用
	return m.ApplyBypassRoutes()
}

// StartAutoRefresh 启动定时自动刷新
func (m *Manager) StartAutoRefresh(interval time.Duration) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.stopChan = make(chan struct{})
	m.running = true
	m.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := m.RefreshRoutes(); err != nil {
					log.Printf("Auto refresh bypass routes failed: %v", err)
				} else {
					log.Printf("Auto refreshed bypass routes")
				}
			case <-m.stopChan:
				return
			}
		}
	}()

	log.Printf("Bypass auto-refresh started with interval %v", interval)
}

// StopAutoRefresh 停止自动刷新
func (m *Manager) StopAutoRefresh() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running && m.stopChan != nil {
		close(m.stopChan)
		m.running = false
		log.Printf("Bypass auto-refresh stopped")
	}
}
