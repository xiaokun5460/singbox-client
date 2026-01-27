package singbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"singbox-client/internal/config"
)

type ConfigGenerator struct {
	dataDir string
}

func NewConfigGenerator(dataDir string) *ConfigGenerator {
	return &ConfigGenerator{dataDir: dataDir}
}

// SingBox config structures for 1.12+
type SingBoxConfig struct {
	Log          *LogConfig    `json:"log,omitempty"`
	DNS          *DNSConfig    `json:"dns,omitempty"`
	Inbounds     []Inbound     `json:"inbounds,omitempty"`
	Outbounds    []Outbound    `json:"outbounds,omitempty"`
	Route        *RouteConfig  `json:"route,omitempty"`
	Experimental *Experimental `json:"experimental,omitempty"`
}

type LogConfig struct {
	Level     string `json:"level,omitempty"`
	Timestamp bool   `json:"timestamp,omitempty"`
	Output    string `json:"output,omitempty"`
}

// DNS Config for sing-box 1.12+
type DNSConfig struct {
	Servers        []DNSServer   `json:"servers,omitempty"`
	Rules          []DNSRule     `json:"rules,omitempty"`
	Final          string        `json:"final,omitempty"`
	Strategy       string        `json:"strategy,omitempty"`
	Independent    bool          `json:"independent_cache,omitempty"`
	CacheCapacity  int           `json:"cache_capacity,omitempty"`
	DisableExpire  bool          `json:"disable_expire,omitempty"`
	ReverseMapping bool          `json:"reverse_mapping,omitempty"`
	ClientSubnet   string        `json:"client_subnet,omitempty"`
	FakeIP         *FakeIPConfig `json:"fakeip,omitempty"`
}

// FakeIPConfig for sing-box DNS
type FakeIPConfig struct {
	Enabled    bool   `json:"enabled"`
	Inet4Range string `json:"inet4_range,omitempty"`
	Inet6Range string `json:"inet6_range,omitempty"`
}

// DNSServer for sing-box 1.12+ with type field
type DNSServer struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	Server         string `json:"server,omitempty"`
	ServerPort     int    `json:"server_port,omitempty"`
	DomainResolver string `json:"domain_resolver,omitempty"`
	Detour         string `json:"detour,omitempty"`
	// FakeIP specific fields
	Inet4Range string `json:"inet4_range,omitempty"`
	Inet6Range string `json:"inet6_range,omitempty"`
}

type DNSRule struct {
	RuleSet       []string `json:"rule_set,omitempty"`
	Server        string   `json:"server,omitempty"`
	Action        string   `json:"action,omitempty"`
	QueryType     []string `json:"query_type,omitempty"`
	DisableCache  bool     `json:"disable_cache,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	Outbound      string   `json:"outbound,omitempty"`
}

type Inbound struct {
	Type                     string   `json:"type"`
	Tag                      string   `json:"tag,omitempty"`
	Address                  []string `json:"address,omitempty"`
	AutoRoute                bool     `json:"auto_route,omitempty"`
	StrictRoute              bool     `json:"strict_route,omitempty"`
	Stack                    string   `json:"stack,omitempty"`
	Listen                   string   `json:"listen,omitempty"`
	ListenPort               int      `json:"listen_port,omitempty"`
	Sniff                    bool     `json:"sniff,omitempty"`
	SniffOverrideDestination bool     `json:"sniff_override_destination,omitempty"`
}

type Outbound struct {
	Type                      string   `json:"type"`
	Tag                       string   `json:"tag"`
	Outbounds                 []string `json:"outbounds,omitempty"`
	Default                   string   `json:"default,omitempty"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`

	// URLTest specific fields
	URL         string `json:"url,omitempty"`
	Interval    string `json:"interval,omitempty"`
	Tolerance   int    `json:"tolerance,omitempty"`
	IdleTimeout string `json:"idle_timeout,omitempty"`

	// Protocol specific fields
	Server     string           `json:"server,omitempty"`
	ServerPort int              `json:"server_port,omitempty"`
	Method     string           `json:"method,omitempty"`
	Password   string           `json:"password,omitempty"`
	UUID       string           `json:"uuid,omitempty"`
	Security   string           `json:"security,omitempty"`
	AlterId    int              `json:"alter_id,omitempty"`
	Network    string           `json:"network,omitempty"`
	TLS        *TLSConfig       `json:"tls,omitempty"`
	Transport  *TransportConfig `json:"transport,omitempty"`
	Flow       string           `json:"flow,omitempty"`
	UDPOverTCP bool             `json:"udp_over_tcp,omitempty"`
	Plugin     string           `json:"plugin,omitempty"`
	PluginOpts string           `json:"plugin_opts,omitempty"`
}

type TLSConfig struct {
	Enabled    bool          `json:"enabled,omitempty"`
	ServerName string        `json:"server_name,omitempty"`
	Insecure   bool          `json:"insecure,omitempty"`
	ALPN       []string      `json:"alpn,omitempty"`
	UTLS       *UTLSConfig   `json:"utls,omitempty"`
	Reality    *RealityConfig `json:"reality,omitempty"`
}

type UTLSConfig struct {
	Enabled     bool   `json:"enabled,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type RealityConfig struct {
	Enabled   bool   `json:"enabled,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
}

type TransportConfig struct {
	Type        string            `json:"type,omitempty"`
	Host        string            `json:"host,omitempty"`
	Path        string            `json:"path,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
}

type RouteConfig struct {
	Rules                 []RouteRule `json:"rules,omitempty"`
	RuleSet               []RuleSet   `json:"rule_set,omitempty"`
	Final                 string      `json:"final,omitempty"`
	AutoDetectInterface   bool        `json:"auto_detect_interface,omitempty"`
	DefaultDomainResolver string      `json:"default_domain_resolver,omitempty"`
}

// RuleSet for remote geoip/geosite rules
type RuleSet struct {
	Tag            string `json:"tag"`
	Type           string `json:"type"`
	Format         string `json:"format"`
	URL            string `json:"url,omitempty"`
	Path           string `json:"path,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty"`
	UpdateInterval string `json:"update_interval,omitempty"`
}

// RouteRule for sing-box 1.12+ with action field
type RouteRule struct {
	Type          string   `json:"type,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	Rules         []any    `json:"rules,omitempty"`
	RuleSet       []string `json:"rule_set,omitempty"`
	Protocol      []string `json:"protocol,omitempty"`
	Port          []int    `json:"port,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	IPIsPrivate   bool     `json:"ip_is_private,omitempty"`
	Action        string   `json:"action,omitempty"`
	Outbound      string   `json:"outbound,omitempty"`
}

type Experimental struct {
	ClashAPI  *ClashAPI  `json:"clash_api,omitempty"`
	CacheFile *CacheFile `json:"cache_file,omitempty"`
	Debug     *Debug     `json:"debug,omitempty"`
}

type ClashAPI struct {
	ExternalController string `json:"external_controller,omitempty"`
	Secret             string `json:"secret,omitempty"`
}

type Debug struct {
	Listen string `json:"listen,omitempty"`
}

type CacheFile struct {
	Enabled     bool   `json:"enabled,omitempty"`
	Path        string `json:"path,omitempty"`
	StoreFakeIP bool   `json:"store_fakeip,omitempty"`
	StoreRDRC   bool   `json:"store_rdrc,omitempty"`
}

func (g *ConfigGenerator) Generate(nodes []Outbound, cfg config.Config, state config.AppState) (*SingBoxConfig, error) {
	sbConfig := &SingBoxConfig{
		Log: &LogConfig{
			Level:     cfg.SingBox.LogLevel,
			Timestamp: true,
		},
	}

	// Generate DNS config
	sbConfig.DNS = g.generateDNS(cfg)

	// Generate inbounds
	sbConfig.Inbounds = g.generateInbounds(cfg)

	// Generate outbounds (no special outbounds in 1.12+)
	sbConfig.Outbounds = g.generateOutbounds(nodes, state)

	// Generate route with rule actions
	sbConfig.Route = g.generateRoute(state, cfg)

	// Add experimental for Clash API and cache
	sbConfig.Experimental = &Experimental{
		ClashAPI: &ClashAPI{
			ExternalController: "127.0.0.1:9090",
		},
		CacheFile: &CacheFile{
			Enabled:     true,
			Path:        filepath.Join(g.dataDir, "singbox", "cache.db"),
			StoreFakeIP: true, // 持久化 FakeIP 映射
			StoreRDRC:   true, // 持久化 DNS 规则检查结果
		},
	}

	return sbConfig, nil
}

func (g *ConfigGenerator) generateDNS(cfg config.Config) *DNSConfig {
	dns := &DNSConfig{
		Final:          "proxy-dns",
		Strategy:       "prefer_ipv4",  // 优先 IPv4，兼容性更好
		Independent:    false,          // 共享缓存，避免同域名重复缓存
		CacheCapacity:  50000,          // 缓存 50000 条记录
		DisableExpire:  false,          // 允许缓存过期，保持 DNS 记录新鲜
		ReverseMapping: true,           // 启用反向映射，日志显示域名而非 IP
	}

	// Get domestic DNS tag
	domesticTag := "domestic-dns"

	// Add domestic DNS servers (UDP type) - no detour means direct
	for i, server := range cfg.DNS.DomesticServers {
		tag := formatTag("domestic-dns", i)
		if i == 0 {
			domesticTag = tag
		}
		dns.Servers = append(dns.Servers, DNSServer{
			Type:   "udp",
			Tag:    tag,
			Server: server,
			// No detour = direct connection
		})
	}

	// Add proxy DNS servers with DoH (DNS over HTTPS) for better privacy
	// Cloudflare DoH is faster than Google (~10-30ms improvement)
	// DoH encrypts DNS queries, preventing proxy server from seeing queries
	dns.Servers = append(dns.Servers,
		// Cloudflare DoH - faster and more private
		DNSServer{
			Type:           "https",
			Tag:            "proxy-doh",
			Server:         "1.1.1.1",
			DomainResolver: domesticTag, // Resolve cloudflare IP using domestic DNS
			Detour:         "proxy",
		},
	)

	// UDP DNS as fallback (Cloudflare is also faster for UDP)
	dns.Servers = append(dns.Servers, DNSServer{
		Type:   "udp",
		Tag:    "proxy-dns",
		Server: "1.1.1.1",
		Detour: "proxy",
	})

	// Add FakeIP server (sing-box 1.12+ format)
	dns.Servers = append(dns.Servers, DNSServer{
		Type:       "fakeip",
		Tag:        "fakeip-dns",
		Inet4Range: "198.18.0.0/15",
		Inet6Range: "fc00::/18",
	})

	// Note: FakeIPConfig is deprecated in 1.12+, ranges are now in the server config

	// DNS rules - comprehensive leak protection
	dns.Rules = []DNSRule{
		// 1. Block browser's built-in DoH to prevent bypassing (force use our DNS)
		// Common DoH providers that browsers use
		{
			Domain: []string{
				"dns.google",
				"dns.google.com",
				"cloudflare-dns.com",
				"one.one.one.one",
				"1dot1dot1dot1.cloudflare-dns.com",
				"dns.cloudflare.com",
				"mozilla.cloudflare-dns.com",
				"dns.quad9.net",
				"doh.opendns.com",
				"dns.adguard.com",
				"doh.dns.sb",
			},
			Server: "proxy-doh", // Force through our DoH
		},

		// 2. HTTPS/SVCB queries not supported by fakeip, use DoH
		{
			QueryType: []string{"HTTPS", "SVCB"},
			Server:    "proxy-doh",
		},

		// 3. PTR (reverse DNS) queries - use domestic to prevent leaks
		{
			QueryType: []string{"PTR"},
			Server:    domesticTag,
		},

		// 4. Private/local domains - never leak to external DNS
		{
			DomainSuffix: []string{
				".local",
				".lan",
				".internal",
				".intranet",
				".home",
				".corp",
				".localhost",
			},
			Server: domesticTag,
		},

		// 5. China sites from comprehensive domain lists - use domestic DNS
		// Using dnsmasq-china-list which is more complete than geosite-cn
		{
			RuleSet: []string{
				"geosite-cn",              // 基础中国域名
				"china-domains",           // dnsmasq-china-list 加速域名
				"apple-cn",                // Apple 中国服务
				"google-cn",               // Google 中国服务
			},
			Server: domesticTag,
		},

		// 6. Ads and tracking domains - block
		{
			RuleSet: []string{"geosite-category-ads-all"},
			Action:  "reject",
		},

		// 7. Known foreign domains use FakeIP (prevents DNS leaks)
		{
			RuleSet: []string{"geosite-geolocation-!cn"},
			Server:  "fakeip-dns",
		},
	}

	// Final: unknown domains use proxy DNS to get real IP
	// This allows BGP IP list to work for accurate China routing
	// Trade-off: proxy server sees DNS queries for unknown domains
	dns.Final = "proxy-dns"

	return dns
}

func (g *ConfigGenerator) generateInbounds(cfg config.Config) []Inbound {
	return []Inbound{
		{
			Type:                     "tun",
			Tag:                      "tun-in",
			Address:                  []string{cfg.Proxy.TUNAddress},
			AutoRoute:                cfg.Proxy.AutoRoute,
			StrictRoute:              cfg.Proxy.StrictRoute,
			Stack:                    cfg.Proxy.TUNStack,
			Sniff:                    true,
			SniffOverrideDestination: true,
		},
	}
}

func (g *ConfigGenerator) generateOutbounds(nodes []Outbound, state config.AppState) []Outbound {
	outbounds := []Outbound{}

	// Collect node tags
	nodeTags := make([]string, 0, len(nodes))
	for _, node := range nodes {
		nodeTags = append(nodeTags, node.Tag)
	}

	// Add selector
	selector := Outbound{
		Type:                      "selector",
		Tag:                       "proxy",
		Outbounds:                 append([]string{"auto"}, nodeTags...),
		Default:                   "auto",
		InterruptExistConnections: true,
	}
	if state.SelectedNode != "" {
		selector.Default = state.SelectedNode
	}
	outbounds = append(outbounds, selector)

	// Add URLTest (auto selection) with optimized settings
	if len(nodeTags) > 0 {
		outbounds = append(outbounds, Outbound{
			Type:                      "urltest",
			Tag:                       "auto",
			Outbounds:                 nodeTags,
			URL:                       "https://www.gstatic.com/generate_204", // Google 连通性测试，快速可靠
			Interval:                  "3m",                                   // 每 3 分钟测试一次
			Tolerance:                 50,                                     // 延迟差异超过 50ms 才切换节点
			IdleTimeout:               "30m",                                  // 空闲 30 分钟后暂停测试
			InterruptExistConnections: true,                                   // 切换节点时中断现有连接
		})
	}

	// Add direct outbound only (no block/dns in 1.12+)
	outbounds = append(outbounds, Outbound{
		Type: "direct",
		Tag:  "direct",
	})

	// Add all node outbounds
	outbounds = append(outbounds, nodes...)

	return outbounds
}

func (g *ConfigGenerator) generateRoute(state config.AppState, cfg config.Config) *RouteConfig {
	// Get domestic DNS tag for default_domain_resolver
	domesticDNSTag := "domestic-dns"
	if len(cfg.DNS.DomesticServers) > 0 {
		domesticDNSTag = formatTag("domestic-dns", 0)
	}

	route := &RouteConfig{
		Final:                 "proxy",
		AutoDetectInterface:   true,
		DefaultDomainResolver: domesticDNSTag,
	}

	// Handle different proxy modes
	switch state.ProxyMode {
	case "direct":
		route.Final = "direct"
	case "global":
		route.Final = "proxy"
	case "rule":
		route.Final = "proxy"
	}

	// Build rules with action field (sing-box 1.12+ format)
	rules := []RouteRule{
		// Sniff rule (required for protocol detection)
		{
			Action: "sniff",
		},
		// Resolve domains to IP for accurate geoip routing
		// This is critical for Solution C - allows BGP IP list to work
		{
			Action: "resolve",
		},
		// DNS hijacking using action instead of outbound
		{
			Protocol: []string{"dns"},
			Action:   "hijack-dns",
		},
		// Block browser's built-in DoH connections (force use system DNS)
		// This prevents browsers from bypassing our DNS settings
		// Note: Don't block dns.google since we use it for our own DoH
		{
			Domain: []string{
				"cloudflare-dns.com",
				"one.one.one.one",
				"1dot1dot1dot1.cloudflare-dns.com",
				"dns.cloudflare.com",
				"mozilla.cloudflare-dns.com",
				"dns.quad9.net",
				"doh.opendns.com",
				"dns.adguard.com",
				"doh.dns.sb",
				"dns11.quad9.net",
				"dns.nextdns.io",
				"doh.cleanbrowsing.org",
				"dns.digitale-gesellschaft.ch",
			},
			Port:   []int{443},
			Action: "reject", // Block browser DoH
		},
		// Block ads and tracking (route level)
		{
			RuleSet: []string{"geosite-category-ads-all"},
			Action:  "reject",
		},
		// Private networks direct
		{
			IPIsPrivate: true,
			Action:      "route",
			Outbound:    "direct",
		},
		// China direct using comprehensive domain lists
		{
			RuleSet: []string{
				"geosite-cn",
				"china-domains",
				"apple-cn",
				"google-cn",
			},
			Action:   "route",
			Outbound: "direct",
		},
		// China direct using BGP-based IP list (more accurate than MaxMind geoip)
		{
			RuleSet:  []string{"chnroutes-bgp"},
			Action:   "route",
			Outbound: "direct",
		},
	}

	// Add custom rules
	for _, rule := range state.CustomRules {
		r := RouteRule{
			Action:   "route",
			Outbound: rule.Outbound,
		}
		// Handle block -> reject action
		if rule.Outbound == "block" {
			r.Action = "reject"
			r.Outbound = ""
		}

		switch rule.Type {
		case "domain":
			r.Domain = []string{rule.Value}
		case "domain_suffix":
			r.DomainSuffix = []string{rule.Value}
		case "geosite":
			r.RuleSet = []string{"geosite-" + rule.Value}
		case "geoip":
			r.RuleSet = []string{"geoip-" + rule.Value}
		}
		rules = append(rules, r)
	}

	route.Rules = rules

	// Use remote rule_set from multiple sources
	// Dreista/sing-box-rule-set-cn provides more accurate BGP-based IP list and comprehensive domain lists
	route.RuleSet = []RuleSet{
		// BGP-based China IP list (more accurate than MaxMind geoip-cn)
		// Source: misakaio/chnroutes2 - updated daily from BGP feed
		{
			Tag:            "chnroutes-bgp",
			Type:           "remote",
			Format:         "binary",
			URL:            "https://testingcf.jsdelivr.net/gh/Dreista/sing-box-rule-set-cn@rule-set/chnroutes.txt.srs",
			DownloadDetour: "direct",
			UpdateInterval: "1d",
		},
		// Comprehensive China domain list from dnsmasq-china-list
		// Much more complete than geosite-cn
		{
			Tag:            "china-domains",
			Type:           "remote",
			Format:         "binary",
			URL:            "https://testingcf.jsdelivr.net/gh/Dreista/sing-box-rule-set-cn@rule-set/accelerated-domains.china.conf.srs",
			DownloadDetour: "direct",
			UpdateInterval: "1d",
		},
		// Apple China services
		{
			Tag:            "apple-cn",
			Type:           "remote",
			Format:         "binary",
			URL:            "https://testingcf.jsdelivr.net/gh/Dreista/sing-box-rule-set-cn@rule-set/apple.china.conf.srs",
			DownloadDetour: "direct",
			UpdateInterval: "1d",
		},
		// Google China services (translate, etc.)
		{
			Tag:            "google-cn",
			Type:           "remote",
			Format:         "binary",
			URL:            "https://testingcf.jsdelivr.net/gh/Dreista/sing-box-rule-set-cn@rule-set/google.china.conf.srs",
			DownloadDetour: "direct",
			UpdateInterval: "1d",
		},
		// Base geosite-cn (fallback)
		{
			Tag:            "geosite-cn",
			Type:           "remote",
			Format:         "binary",
			URL:            "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs",
			DownloadDetour: "direct",
			UpdateInterval: "1d",
		},
		// Domain rules - Foreign (for FakeIP)
		{
			Tag:            "geosite-geolocation-!cn",
			Type:           "remote",
			Format:         "binary",
			URL:            "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-geolocation-!cn.srs",
			DownloadDetour: "direct",
			UpdateInterval: "1d",
		},
		// Ads blocking
		{
			Tag:            "geosite-category-ads-all",
			Type:           "remote",
			Format:         "binary",
			URL:            "https://testingcf.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ads-all.srs",
			DownloadDetour: "direct",
			UpdateInterval: "1d",
		},
	}

	return route
}

func (g *ConfigGenerator) SaveConfig(config *SingBoxConfig, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func formatTag(prefix string, index int) string {
	if index == 0 {
		return prefix
	}
	return fmt.Sprintf("%s-%d", prefix, index)
}
