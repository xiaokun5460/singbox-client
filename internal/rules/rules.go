package rules

import (
	"fmt"

	"singbox-client/internal/config"
)

type RuleManager struct {
	cfgMgr *config.Manager
}

func NewRuleManager() *RuleManager {
	return &RuleManager{
		cfgMgr: config.GetManager(),
	}
}

// GetProxyMode returns the current proxy mode
func (rm *RuleManager) GetProxyMode() string {
	state := rm.cfgMgr.GetState()
	return state.ProxyMode
}

// SetProxyMode sets the proxy mode (global, rule, direct)
func (rm *RuleManager) SetProxyMode(mode string) error {
	validModes := map[string]bool{"global": true, "rule": true, "direct": true}
	if !validModes[mode] {
		return fmt.Errorf("invalid proxy mode: %s (valid: global, rule, direct)", mode)
	}
	return rm.cfgMgr.SetProxyMode(mode)
}

// GetCustomRules returns all custom rules
func (rm *RuleManager) GetCustomRules() []config.CustomRule {
	return rm.cfgMgr.GetCustomRules()
}

// SetCustomRules updates all custom rules
func (rm *RuleManager) SetCustomRules(rules []config.CustomRule) error {
	for i := range rules {
		if err := rm.validateRule(&rules[i]); err != nil {
			return err
		}
	}
	return rm.cfgMgr.SetCustomRules(rules)
}

// AddCustomRule adds a new custom rule
func (rm *RuleManager) AddCustomRule(rule config.CustomRule) error {
	if err := rm.validateRule(&rule); err != nil {
		return err
	}
	rules := rm.cfgMgr.GetCustomRules()
	rules = append(rules, rule)
	return rm.cfgMgr.SetCustomRules(rules)
}

// RemoveCustomRule removes a custom rule by index
func (rm *RuleManager) RemoveCustomRule(index int) error {
	rules := rm.cfgMgr.GetCustomRules()
	if index < 0 || index >= len(rules) {
		return fmt.Errorf("invalid rule index: %d (valid: 0-%d)", index, len(rules)-1)
	}
	rules = append(rules[:index], rules[index+1:]...)
	return rm.cfgMgr.SetCustomRules(rules)
}

// validateRule validates a custom rule
func (rm *RuleManager) validateRule(rule *config.CustomRule) error {
	validTypes := map[string]bool{
		"domain": true, "domain_suffix": true, "ip_cidr": true,
		"geosite": true, "geoip": true,
	}
	if !validTypes[rule.Type] {
		return fmt.Errorf("invalid rule type: %s", rule.Type)
	}

	validOutbounds := map[string]bool{"proxy": true, "direct": true, "block": true}
	if !validOutbounds[rule.Outbound] {
		return fmt.Errorf("invalid rule outbound: %s", rule.Outbound)
	}

	if rule.Value == "" {
		return fmt.Errorf("rule value cannot be empty")
	}

	return nil
}

// GetDefaultRules returns the default built-in rules description
func (rm *RuleManager) GetDefaultRules() []RuleDescription {
	return []RuleDescription{
		{
			Name:        "DNS hijacking",
			Description: "Redirect DNS queries to sing-box DNS module",
			Enabled:     true,
		},
		{
			Name:        "Private networks",
			Description: "Direct connection for private IP ranges (10.x, 192.168.x, 172.16.x)",
			Enabled:     true,
		},
		{
			Name:        "China domains",
			Description: "Direct connection for Chinese domains (geosite:cn)",
			Enabled:     true,
		},
		{
			Name:        "China IPs",
			Description: "Direct connection for Chinese IPs (geoip:cn)",
			Enabled:     true,
		},
	}
}

type RuleDescription struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// GetAvailableGeosites returns commonly used geosite values
func (rm *RuleManager) GetAvailableGeosites() []string {
	return []string{
		"cn",
		"geolocation-cn",
		"geolocation-!cn",
		"google",
		"facebook",
		"twitter",
		"telegram",
		"youtube",
		"netflix",
		"spotify",
		"apple",
		"microsoft",
		"github",
		"steam",
		"openai",
		"category-ads",
		"category-ads-all",
	}
}

// GetAvailableGeoips returns commonly used geoip values
func (rm *RuleManager) GetAvailableGeoips() []string {
	return []string{
		"cn",
		"private",
		"us",
		"jp",
		"kr",
		"hk",
		"tw",
		"sg",
	}
}
