package subscription

import (
	"singbox-client/internal/singbox"
)

type Converter struct{}

func NewConverter() *Converter {
	return &Converter{}
}

func (c *Converter) Convert(proxies []ClashProxy) []singbox.Outbound {
	var outbounds []singbox.Outbound

	for _, proxy := range proxies {
		outbound := c.convertProxy(proxy)
		if outbound != nil {
			outbounds = append(outbounds, *outbound)
		}
	}

	return outbounds
}

func (c *Converter) convertProxy(proxy ClashProxy) *singbox.Outbound {
	switch proxy.Type {
	case "ss", "shadowsocks":
		return c.convertShadowsocks(proxy)
	case "vmess":
		return c.convertVMess(proxy)
	case "trojan":
		return c.convertTrojan(proxy)
	case "vless":
		return c.convertVLESS(proxy)
	case "hysteria2", "hy2":
		return c.convertHysteria2(proxy)
	default:
		return nil
	}
}

func (c *Converter) convertShadowsocks(proxy ClashProxy) *singbox.Outbound {
	outbound := &singbox.Outbound{
		Type:       "shadowsocks",
		Tag:        proxy.Name,
		Server:     proxy.Server,
		ServerPort: proxy.Port,
		Method:     proxy.Method,
		Password:   proxy.Password,
	}

	if proxy.Method == "" {
		outbound.Method = proxy.Cipher
	}

	// Handle plugin
	if proxy.Plugin != "" {
		outbound.Plugin = proxy.Plugin
		if proxy.PluginOpts != nil {
			opts := ""
			for k, v := range proxy.PluginOpts {
				if opts != "" {
					opts += ";"
				}
				switch val := v.(type) {
				case string:
					opts += k + "=" + val
				case bool:
					if val {
						opts += k
					}
				}
			}
			outbound.PluginOpts = opts
		}
	}

	return outbound
}

func (c *Converter) convertVMess(proxy ClashProxy) *singbox.Outbound {
	outbound := &singbox.Outbound{
		Type:       "vmess",
		Tag:        proxy.Name,
		Server:     proxy.Server,
		ServerPort: proxy.Port,
		UUID:       proxy.UUID,
		Security:   proxy.Cipher,
		AlterId:    proxy.AlterId,
	}

	if outbound.Security == "" {
		outbound.Security = "auto"
	}

	// TLS
	if proxy.TLS {
		outbound.TLS = &singbox.TLSConfig{
			Enabled:    true,
			ServerName: proxy.ServerName,
			Insecure:   proxy.SkipCertVerify,
		}
		if proxy.SNI != "" {
			outbound.TLS.ServerName = proxy.SNI
		}
		if len(proxy.ALPN) > 0 {
			outbound.TLS.ALPN = proxy.ALPN
		}
		if proxy.ClientFingerprint != "" || proxy.Fingerprint != "" {
			fp := proxy.ClientFingerprint
			if fp == "" {
				fp = proxy.Fingerprint
			}
			outbound.TLS.UTLS = &singbox.UTLSConfig{
				Enabled:     true,
				Fingerprint: fp,
			}
		}
	}

	// Transport
	if proxy.Network != "" && proxy.Network != "tcp" {
		outbound.Transport = c.convertTransport(proxy)
	}

	return outbound
}

func (c *Converter) convertTrojan(proxy ClashProxy) *singbox.Outbound {
	outbound := &singbox.Outbound{
		Type:       "trojan",
		Tag:        proxy.Name,
		Server:     proxy.Server,
		ServerPort: proxy.Port,
		Password:   proxy.Password,
	}

	// TLS is always enabled for Trojan
	outbound.TLS = &singbox.TLSConfig{
		Enabled:    true,
		ServerName: proxy.ServerName,
		Insecure:   proxy.SkipCertVerify,
	}
	if proxy.SNI != "" {
		outbound.TLS.ServerName = proxy.SNI
	}
	if len(proxy.ALPN) > 0 {
		outbound.TLS.ALPN = proxy.ALPN
	}
	if proxy.ClientFingerprint != "" || proxy.Fingerprint != "" {
		fp := proxy.ClientFingerprint
		if fp == "" {
			fp = proxy.Fingerprint
		}
		outbound.TLS.UTLS = &singbox.UTLSConfig{
			Enabled:     true,
			Fingerprint: fp,
		}
	}

	// Transport
	if proxy.Network != "" && proxy.Network != "tcp" {
		outbound.Transport = c.convertTransport(proxy)
	}

	return outbound
}

func (c *Converter) convertVLESS(proxy ClashProxy) *singbox.Outbound {
	outbound := &singbox.Outbound{
		Type:       "vless",
		Tag:        proxy.Name,
		Server:     proxy.Server,
		ServerPort: proxy.Port,
		UUID:       proxy.UUID,
		Flow:       proxy.Flow,
	}

	// TLS
	if proxy.TLS {
		outbound.TLS = &singbox.TLSConfig{
			Enabled:    true,
			ServerName: proxy.ServerName,
			Insecure:   proxy.SkipCertVerify,
		}
		if proxy.SNI != "" {
			outbound.TLS.ServerName = proxy.SNI
		}
		if len(proxy.ALPN) > 0 {
			outbound.TLS.ALPN = proxy.ALPN
		}
		if proxy.ClientFingerprint != "" || proxy.Fingerprint != "" {
			fp := proxy.ClientFingerprint
			if fp == "" {
				fp = proxy.Fingerprint
			}
			outbound.TLS.UTLS = &singbox.UTLSConfig{
				Enabled:     true,
				Fingerprint: fp,
			}
		}

		// Reality
		if proxy.RealityOpts != nil {
			outbound.TLS.Reality = &singbox.RealityConfig{
				Enabled:   true,
				PublicKey: proxy.RealityOpts.PublicKey,
				ShortID:   proxy.RealityOpts.ShortID,
			}
		}
	}

	// Transport
	if proxy.Network != "" && proxy.Network != "tcp" {
		outbound.Transport = c.convertTransport(proxy)
	}

	return outbound
}

func (c *Converter) convertHysteria2(proxy ClashProxy) *singbox.Outbound {
	outbound := &singbox.Outbound{
		Type:       "hysteria2",
		Tag:        proxy.Name,
		Server:     proxy.Server,
		ServerPort: proxy.Port,
		Password:   proxy.Password,
	}

	// TLS
	outbound.TLS = &singbox.TLSConfig{
		Enabled:    true,
		ServerName: proxy.ServerName,
		Insecure:   proxy.SkipCertVerify,
	}
	if proxy.SNI != "" {
		outbound.TLS.ServerName = proxy.SNI
	}

	return outbound
}

func (c *Converter) convertTransport(proxy ClashProxy) *singbox.TransportConfig {
	transport := &singbox.TransportConfig{}

	switch proxy.Network {
	case "ws":
		transport.Type = "ws"
		if proxy.WSOpts != nil {
			transport.Path = proxy.WSOpts.Path
			if host, ok := proxy.WSOpts.Headers["Host"]; ok {
				transport.Headers = map[string]string{"Host": host}
			}
		}
	case "grpc":
		transport.Type = "grpc"
		if proxy.GrpcOpts != nil {
			transport.ServiceName = proxy.GrpcOpts.GrpcServiceName
		}
	case "h2":
		transport.Type = "http"
		if proxy.H2Opts != nil {
			transport.Path = proxy.H2Opts.Path
			if len(proxy.H2Opts.Host) > 0 {
				transport.Host = proxy.H2Opts.Host[0]
			}
		}
	case "http":
		transport.Type = "http"
	default:
		return nil
	}

	return transport
}
