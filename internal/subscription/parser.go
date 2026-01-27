package subscription

import (
	"encoding/base64"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Clash YAML structures
type ClashConfig struct {
	Proxies []ClashProxy `yaml:"proxies"`
}

type ClashProxy struct {
	Name           string                 `yaml:"name"`
	Type           string                 `yaml:"type"`
	Server         string                 `yaml:"server"`
	Port           int                    `yaml:"port"`
	Password       string                 `yaml:"password,omitempty"`
	UUID           string                 `yaml:"uuid,omitempty"`
	AlterId        int                    `yaml:"alterId,omitempty"`
	Cipher         string                 `yaml:"cipher,omitempty"`
	Method         string                 `yaml:"method,omitempty"`
	UDP            bool                   `yaml:"udp,omitempty"`
	TLS            bool                   `yaml:"tls,omitempty"`
	SkipCertVerify bool                   `yaml:"skip-cert-verify,omitempty"`
	ServerName     string                 `yaml:"servername,omitempty"`
	SNI            string                 `yaml:"sni,omitempty"`
	Network        string                 `yaml:"network,omitempty"`
	Plugin         string                 `yaml:"plugin,omitempty"`
	PluginOpts     map[string]interface{} `yaml:"plugin-opts,omitempty"`
	WSOpts         *WSOptions             `yaml:"ws-opts,omitempty"`
	GrpcOpts       *GRPCOptions           `yaml:"grpc-opts,omitempty"`
	H2Opts         *H2Options             `yaml:"h2-opts,omitempty"`
	RealityOpts    *RealityOptions        `yaml:"reality-opts,omitempty"`
	Flow           string                 `yaml:"flow,omitempty"`
	ClientFingerprint string              `yaml:"client-fingerprint,omitempty"`
	Fingerprint    string                 `yaml:"fingerprint,omitempty"`
	ALPN           []string               `yaml:"alpn,omitempty"`
}

type WSOptions struct {
	Path                string            `yaml:"path,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty"`
	MaxEarlyData        int               `yaml:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `yaml:"early-data-header-name,omitempty"`
}

type GRPCOptions struct {
	GrpcServiceName string `yaml:"grpc-service-name,omitempty"`
}

type H2Options struct {
	Host []string `yaml:"host,omitempty"`
	Path string   `yaml:"path,omitempty"`
}

type RealityOptions struct {
	PublicKey string `yaml:"public-key,omitempty"`
	ShortID   string `yaml:"short-id,omitempty"`
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(data []byte) ([]ClashProxy, error) {
	// Try to decode as base64 first
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		data = decoded
	} else {
		// Try URL-safe base64
		decoded, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err == nil {
			data = decoded
		}
	}

	// Try parsing as Clash YAML
	var clashConfig ClashConfig
	if err := yaml.Unmarshal(data, &clashConfig); err == nil && len(clashConfig.Proxies) > 0 {
		return clashConfig.Proxies, nil
	}

	// Try parsing as plain proxy list
	var proxies []ClashProxy
	if err := yaml.Unmarshal(data, &proxies); err == nil && len(proxies) > 0 {
		return proxies, nil
	}

	// Try parsing as line-based format (base64 encoded links)
	lines := strings.Split(string(data), "\n")
	var lineProxies []ClashProxy
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		proxy, err := p.parseURI(line)
		if err != nil {
			continue
		}
		lineProxies = append(lineProxies, proxy)
	}
	if len(lineProxies) > 0 {
		return lineProxies, nil
	}

	return nil, fmt.Errorf("unable to parse subscription data")
}

func (p *Parser) parseURI(uri string) (ClashProxy, error) {
	var proxy ClashProxy

	switch {
	case strings.HasPrefix(uri, "ss://"):
		return p.parseSS(uri)
	case strings.HasPrefix(uri, "vmess://"):
		return p.parseVMess(uri)
	case strings.HasPrefix(uri, "trojan://"):
		return p.parseTrojan(uri)
	case strings.HasPrefix(uri, "vless://"):
		return p.parseVLESS(uri)
	case strings.HasPrefix(uri, "hysteria2://") || strings.HasPrefix(uri, "hy2://"):
		return p.parseHysteria2(uri)
	default:
		return proxy, fmt.Errorf("unsupported protocol: %s", uri)
	}
}

func (p *Parser) parseSS(uri string) (ClashProxy, error) {
	proxy := ClashProxy{Type: "ss"}

	// Remove ss:// prefix
	uri = strings.TrimPrefix(uri, "ss://")

	// Split by # for name
	parts := strings.SplitN(uri, "#", 2)
	if len(parts) == 2 {
		proxy.Name = decodeURIComponent(parts[1])
	}
	uri = parts[0]

	// Handle SIP002 format (base64@server:port) vs legacy format
	if strings.Contains(uri, "@") {
		atParts := strings.SplitN(uri, "@", 2)
		methodPassword := atParts[0]
		serverPort := atParts[1]

		// Decode method:password
		decoded, err := base64.RawURLEncoding.DecodeString(methodPassword)
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(methodPassword)
		}
		if err == nil {
			methodPassword = string(decoded)
		}

		mpParts := strings.SplitN(methodPassword, ":", 2)
		if len(mpParts) == 2 {
			proxy.Method = mpParts[0]
			proxy.Password = mpParts[1]
		}

		// Parse server:port
		serverPortParts := strings.SplitN(serverPort, ":", 2)
		if len(serverPortParts) == 2 {
			proxy.Server = serverPortParts[0]
			fmt.Sscanf(serverPortParts[1], "%d", &proxy.Port)
		}
	} else {
		// Legacy format: base64(method:password@server:port)
		decoded, err := base64.StdEncoding.DecodeString(uri)
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(uri)
		}
		if err != nil {
			return proxy, fmt.Errorf("failed to decode ss uri: %w", err)
		}

		content := string(decoded)
		atParts := strings.SplitN(content, "@", 2)
		if len(atParts) != 2 {
			return proxy, fmt.Errorf("invalid ss format")
		}

		mpParts := strings.SplitN(atParts[0], ":", 2)
		if len(mpParts) == 2 {
			proxy.Method = mpParts[0]
			proxy.Password = mpParts[1]
		}

		serverPortParts := strings.SplitN(atParts[1], ":", 2)
		if len(serverPortParts) == 2 {
			proxy.Server = serverPortParts[0]
			fmt.Sscanf(serverPortParts[1], "%d", &proxy.Port)
		}
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

func (p *Parser) parseVMess(uri string) (ClashProxy, error) {
	proxy := ClashProxy{Type: "vmess"}

	// Remove vmess:// prefix
	uri = strings.TrimPrefix(uri, "vmess://")

	// Base64 decode
	decoded, err := base64.StdEncoding.DecodeString(uri)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(uri)
	}
	if err != nil {
		return proxy, fmt.Errorf("failed to decode vmess uri: %w", err)
	}

	// Parse JSON
	var vmessConfig map[string]interface{}
	if err := yaml.Unmarshal(decoded, &vmessConfig); err != nil {
		return proxy, fmt.Errorf("failed to parse vmess config: %w", err)
	}

	if v, ok := vmessConfig["ps"].(string); ok {
		proxy.Name = v
	}
	if v, ok := vmessConfig["add"].(string); ok {
		proxy.Server = v
	}
	if v, ok := vmessConfig["port"]; ok {
		switch port := v.(type) {
		case int:
			proxy.Port = port
		case float64:
			proxy.Port = int(port)
		case string:
			fmt.Sscanf(port, "%d", &proxy.Port)
		}
	}
	if v, ok := vmessConfig["id"].(string); ok {
		proxy.UUID = v
	}
	if v, ok := vmessConfig["aid"]; ok {
		switch aid := v.(type) {
		case int:
			proxy.AlterId = aid
		case float64:
			proxy.AlterId = int(aid)
		case string:
			fmt.Sscanf(aid, "%d", &proxy.AlterId)
		}
	}
	if v, ok := vmessConfig["scy"].(string); ok {
		proxy.Cipher = v
	} else {
		proxy.Cipher = "auto"
	}
	if v, ok := vmessConfig["net"].(string); ok {
		proxy.Network = v
	}
	if v, ok := vmessConfig["type"].(string); ok && v == "http" {
		proxy.Network = "http"
	}
	if v, ok := vmessConfig["tls"].(string); ok && v == "tls" {
		proxy.TLS = true
	}
	if v, ok := vmessConfig["sni"].(string); ok {
		proxy.ServerName = v
	}
	if v, ok := vmessConfig["host"].(string); ok && proxy.Network == "ws" {
		proxy.WSOpts = &WSOptions{
			Headers: map[string]string{"Host": v},
		}
	}
	if v, ok := vmessConfig["path"].(string); ok {
		if proxy.WSOpts == nil {
			proxy.WSOpts = &WSOptions{}
		}
		proxy.WSOpts.Path = v
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

func (p *Parser) parseTrojan(uri string) (ClashProxy, error) {
	proxy := ClashProxy{Type: "trojan", TLS: true}

	// Remove trojan:// prefix
	uri = strings.TrimPrefix(uri, "trojan://")

	// Split by # for name
	parts := strings.SplitN(uri, "#", 2)
	if len(parts) == 2 {
		proxy.Name = decodeURIComponent(parts[1])
	}
	uri = parts[0]

	// Split by ? for params
	params := make(map[string]string)
	if idx := strings.Index(uri, "?"); idx != -1 {
		paramStr := uri[idx+1:]
		uri = uri[:idx]
		for _, param := range strings.Split(paramStr, "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 {
				params[kv[0]] = decodeURIComponent(kv[1])
			}
		}
	}

	// Parse password@server:port
	atParts := strings.SplitN(uri, "@", 2)
	if len(atParts) != 2 {
		return proxy, fmt.Errorf("invalid trojan format")
	}
	proxy.Password = atParts[0]

	serverPort := atParts[1]
	if idx := strings.LastIndex(serverPort, ":"); idx != -1 {
		proxy.Server = serverPort[:idx]
		fmt.Sscanf(serverPort[idx+1:], "%d", &proxy.Port)
	}

	// Apply params
	if v, ok := params["sni"]; ok {
		proxy.ServerName = v
	}
	if v, ok := params["type"]; ok {
		proxy.Network = v
	}
	if v, ok := params["path"]; ok {
		proxy.WSOpts = &WSOptions{Path: v}
	}
	if v, ok := params["host"]; ok {
		if proxy.WSOpts == nil {
			proxy.WSOpts = &WSOptions{}
		}
		proxy.WSOpts.Headers = map[string]string{"Host": v}
	}
	if v, ok := params["serviceName"]; ok {
		proxy.GrpcOpts = &GRPCOptions{GrpcServiceName: v}
	}
	if v, ok := params["allowInsecure"]; ok && v == "1" {
		proxy.SkipCertVerify = true
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

func (p *Parser) parseVLESS(uri string) (ClashProxy, error) {
	proxy := ClashProxy{Type: "vless"}

	// Remove vless:// prefix
	uri = strings.TrimPrefix(uri, "vless://")

	// Split by # for name
	parts := strings.SplitN(uri, "#", 2)
	if len(parts) == 2 {
		proxy.Name = decodeURIComponent(parts[1])
	}
	uri = parts[0]

	// Split by ? for params
	params := make(map[string]string)
	if idx := strings.Index(uri, "?"); idx != -1 {
		paramStr := uri[idx+1:]
		uri = uri[:idx]
		for _, param := range strings.Split(paramStr, "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 {
				params[kv[0]] = decodeURIComponent(kv[1])
			}
		}
	}

	// Parse uuid@server:port
	atParts := strings.SplitN(uri, "@", 2)
	if len(atParts) != 2 {
		return proxy, fmt.Errorf("invalid vless format")
	}
	proxy.UUID = atParts[0]

	serverPort := atParts[1]
	if idx := strings.LastIndex(serverPort, ":"); idx != -1 {
		proxy.Server = serverPort[:idx]
		fmt.Sscanf(serverPort[idx+1:], "%d", &proxy.Port)
	}

	// Apply params
	if v, ok := params["security"]; ok && v == "tls" {
		proxy.TLS = true
	}
	if v, ok := params["security"]; ok && v == "reality" {
		proxy.TLS = true
		proxy.RealityOpts = &RealityOptions{}
		if pk, ok := params["pbk"]; ok {
			proxy.RealityOpts.PublicKey = pk
		}
		if sid, ok := params["sid"]; ok {
			proxy.RealityOpts.ShortID = sid
		}
	}
	if v, ok := params["sni"]; ok {
		proxy.ServerName = v
	}
	if v, ok := params["type"]; ok {
		proxy.Network = v
	}
	if v, ok := params["flow"]; ok {
		proxy.Flow = v
	}
	if v, ok := params["path"]; ok {
		proxy.WSOpts = &WSOptions{Path: v}
	}
	if v, ok := params["host"]; ok {
		if proxy.WSOpts == nil {
			proxy.WSOpts = &WSOptions{}
		}
		proxy.WSOpts.Headers = map[string]string{"Host": v}
	}
	if v, ok := params["serviceName"]; ok {
		proxy.GrpcOpts = &GRPCOptions{GrpcServiceName: v}
	}
	if v, ok := params["fp"]; ok {
		proxy.ClientFingerprint = v
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

func (p *Parser) parseHysteria2(uri string) (ClashProxy, error) {
	proxy := ClashProxy{Type: "hysteria2"}

	// Remove prefix
	uri = strings.TrimPrefix(uri, "hysteria2://")
	uri = strings.TrimPrefix(uri, "hy2://")

	// Split by # for name
	parts := strings.SplitN(uri, "#", 2)
	if len(parts) == 2 {
		proxy.Name = decodeURIComponent(parts[1])
	}
	uri = parts[0]

	// Split by ? for params
	params := make(map[string]string)
	if idx := strings.Index(uri, "?"); idx != -1 {
		paramStr := uri[idx+1:]
		uri = uri[:idx]
		for _, param := range strings.Split(paramStr, "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 {
				params[kv[0]] = decodeURIComponent(kv[1])
			}
		}
	}

	// Parse password@server:port
	atParts := strings.SplitN(uri, "@", 2)
	if len(atParts) != 2 {
		return proxy, fmt.Errorf("invalid hysteria2 format")
	}
	proxy.Password = atParts[0]

	serverPort := atParts[1]
	if idx := strings.LastIndex(serverPort, ":"); idx != -1 {
		proxy.Server = serverPort[:idx]
		fmt.Sscanf(serverPort[idx+1:], "%d", &proxy.Port)
	}

	// Apply params
	if v, ok := params["sni"]; ok {
		proxy.ServerName = v
	}
	if v, ok := params["insecure"]; ok && v == "1" {
		proxy.SkipCertVerify = true
	}

	if proxy.Name == "" {
		proxy.Name = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
	}

	return proxy, nil
}

func decodeURIComponent(s string) string {
	result := strings.Builder{}
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			var val int
			_, err := fmt.Sscanf(s[i+1:i+3], "%x", &val)
			if err == nil {
				result.WriteByte(byte(val))
				i += 3
				continue
			}
		}
		if s[i] == '+' {
			result.WriteByte(' ')
		} else {
			result.WriteByte(s[i])
		}
		i++
	}
	return result.String()
}
