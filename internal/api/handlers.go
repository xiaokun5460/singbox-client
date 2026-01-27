package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"singbox-client/internal/config"
	"singbox-client/internal/rules"
	"singbox-client/internal/singbox"
	"singbox-client/internal/subscription"
)

type Handlers struct {
	cfgMgr     *config.Manager
	processMgr *singbox.ProcessManager
	updater    *subscription.Updater
	generator  *singbox.ConfigGenerator
	rulesMgr   *rules.RuleManager
}

func NewHandlers() *Handlers {
	cfgMgr := config.GetManager()
	return &Handlers{
		cfgMgr:     cfgMgr,
		processMgr: singbox.GetProcessManager(),
		updater:    subscription.GetUpdater(),
		generator:  singbox.NewConfigGenerator(cfgMgr.GetDataDir()),
		rulesMgr:   rules.NewRuleManager(),
	}
}

type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func (h *Handlers) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Success: true, Data: data})
}

func (h *Handlers) sendError(w http.ResponseWriter, status int, err string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{Success: false, Error: err})
}

// Status handlers

func (h *Handlers) GetStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	status := h.processMgr.GetStatus()

	// Add additional info
	exists, version := h.processMgr.CheckBinary()
	nodes := h.updater.GetNodes()
	state := h.cfgMgr.GetState()

	data := map[string]interface{}{
		"state":         status.State,
		"pid":           status.PID,
		"binary_exists": exists,
		"version":       strings.TrimSpace(version),
		"node_count":    len(nodes),
		"selected_node": state.SelectedNode,
		"proxy_mode":    state.ProxyMode,
		"last_update":   h.updater.GetLastUpdate(),
	}

	h.sendJSON(w, data)
}

// Process control handlers

func (h *Handlers) Start(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Generate config before starting
	if err := h.generateConfig(); err != nil {
		h.sendError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to generate config: %v", err))
		return
	}

	if err := h.processMgr.Start(); err != nil {
		h.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.sendJSON(w, map[string]string{"status": "started"})
}

func (h *Handlers) Stop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if err := h.processMgr.Stop(); err != nil {
		h.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.sendJSON(w, map[string]string{"status": "stopped"})
}

func (h *Handlers) Restart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Generate config before restarting
	if err := h.generateConfig(); err != nil {
		h.sendError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to generate config: %v", err))
		return
	}

	if err := h.processMgr.Restart(); err != nil {
		h.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.sendJSON(w, map[string]string{"status": "restarted"})
}

// Subscription handlers

func (h *Handlers) HandleSubscriptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		subs := h.cfgMgr.GetSubscriptions()
		h.sendJSON(w, subs)
	case "POST":
		var sub config.Subscription
		if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
			h.sendError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if sub.URL == "" {
			h.sendError(w, http.StatusBadRequest, "URL is required")
			return
		}

		sub.ID = subscription.GenerateID()
		if sub.Name == "" {
			sub.Name = "Subscription " + sub.ID[:6]
		}

		if err := h.cfgMgr.AddSubscription(sub); err != nil {
			h.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Fetch subscription in background
		go h.updater.RefreshSubscription(sub)

		h.sendJSON(w, sub)
	default:
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *Handlers) HandleSubscriptionByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/subscriptions/")
	if id == "" {
		h.sendError(w, http.StatusBadRequest, "Subscription ID required")
		return
	}

	switch r.Method {
	case "PUT":
		var sub config.Subscription
		if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
			h.sendError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		sub.ID = id

		if err := h.cfgMgr.UpdateSubscription(sub); err != nil {
			h.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}

		h.sendJSON(w, sub)
	case "DELETE":
		if err := h.cfgMgr.DeleteSubscription(id); err != nil {
			h.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err := h.updater.DeleteSubscriptionCache(id); err != nil {
			// Log warning but don't fail - subscription is already deleted
			log.Printf("Warning: failed to delete subscription cache: %v", err)
		}

		h.sendJSON(w, map[string]string{"status": "deleted"})
	default:
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *Handlers) RefreshSubscriptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if err := h.updater.RefreshAll(); err != nil {
		h.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.sendJSON(w, map[string]string{"status": "refreshed"})
}

// Node handlers

type NodeInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Selected bool   `json:"selected"`
	Latency  int    `json:"latency,omitempty"`
}

func (h *Handlers) GetNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	nodes := h.updater.GetNodes()
	state := h.cfgMgr.GetState()

	nodeInfos := make([]NodeInfo, 0, len(nodes))
	for _, node := range nodes {
		nodeInfos = append(nodeInfos, NodeInfo{
			Name:     node.Tag,
			Type:     node.Type,
			Server:   node.Server,
			Port:     node.ServerPort,
			Selected: node.Tag == state.SelectedNode,
		})
	}

	h.sendJSON(w, nodeInfos)
}

func (h *Handlers) HandleNodeAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/nodes/")
	parts := strings.Split(path, "/")

	if len(parts) < 2 {
		h.sendError(w, http.StatusBadRequest, "Invalid path")
		return
	}

	nodeName := parts[0]
	action := parts[1]

	switch action {
	case "select":
		if r.Method != "POST" {
			h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		if err := h.cfgMgr.SetSelectedNode(nodeName); err != nil {
			h.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Regenerate config if running
		if h.processMgr.GetState() == singbox.StateRunning {
			if err := h.generateConfig(); err != nil {
				h.sendError(w, http.StatusInternalServerError, err.Error())
				return
			}
			h.processMgr.Restart()
		}

		h.sendJSON(w, map[string]string{"selected": nodeName})

	case "test":
		if r.Method != "POST" {
			h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		// Find node
		nodes := h.updater.GetNodes()
		var targetNode *singbox.Outbound
		for _, node := range nodes {
			if node.Tag == nodeName {
				targetNode = &node
				break
			}
		}

		if targetNode == nil {
			h.sendError(w, http.StatusNotFound, "Node not found")
			return
		}

		// Test latency
		latency, err := h.testNodeLatency(targetNode.Server, targetNode.ServerPort)
		if err != nil {
			h.sendJSON(w, map[string]interface{}{
				"node":    nodeName,
				"latency": -1,
				"error":   err.Error(),
			})
			return
		}

		h.sendJSON(w, map[string]interface{}{
			"node":    nodeName,
			"latency": latency,
		})

	default:
		h.sendError(w, http.StatusBadRequest, "Invalid action")
	}
}

func (h *Handlers) testNodeLatency(server string, port int) (int, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server, port), 5*time.Second)
	if err != nil {
		return -1, err
	}
	conn.Close()
	return int(time.Since(start).Milliseconds()), nil
}

// Config handlers

func (h *Handlers) HandleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		cfg := h.cfgMgr.GetConfig()
		h.sendJSON(w, cfg)
	case "PUT":
		var cfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			h.sendError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if err := h.cfgMgr.UpdateConfig(cfg); err != nil {
			h.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}

		h.sendJSON(w, cfg)
	default:
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// Rules handlers

func (h *Handlers) HandleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		rules := h.rulesMgr.GetCustomRules()
		defaultRules := h.rulesMgr.GetDefaultRules()
		geosites := h.rulesMgr.GetAvailableGeosites()
		geoips := h.rulesMgr.GetAvailableGeoips()

		h.sendJSON(w, map[string]interface{}{
			"custom_rules":   rules,
			"default_rules":  defaultRules,
			"geosite_values": geosites,
			"geoip_values":   geoips,
		})
	case "PUT":
		var rules []config.CustomRule
		if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
			h.sendError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if err := h.rulesMgr.SetCustomRules(rules); err != nil {
			h.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Regenerate config if running
		if h.processMgr.GetState() == singbox.StateRunning {
			if err := h.generateConfig(); err != nil {
				h.sendError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to generate config: %v", err))
				return
			}
			if err := h.processMgr.Restart(); err != nil {
				h.sendError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to restart: %v", err))
				return
			}
		}

		h.sendJSON(w, rules)
	default:
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *Handlers) HandleProxyMode(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		mode := h.rulesMgr.GetProxyMode()
		h.sendJSON(w, map[string]string{"mode": mode})
	case "PUT":
		var req struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.sendError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if err := h.rulesMgr.SetProxyMode(req.Mode); err != nil {
			h.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Regenerate config if running
		if h.processMgr.GetState() == singbox.StateRunning {
			if err := h.generateConfig(); err != nil {
				h.sendError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to generate config: %v", err))
				return
			}
			if err := h.processMgr.Restart(); err != nil {
				h.sendError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to restart: %v", err))
				return
			}
		}

		h.sendJSON(w, map[string]string{"mode": req.Mode})
	default:
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// Logs handler - returns recent logs as JSON
func (h *Handlers) GetLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	logs := h.processMgr.GetLogs(100)
	h.sendJSON(w, logs)
}

// GetLogsSSE handles Server-Sent Events for real-time logs
func (h *Handlers) GetLogsSSE(w http.ResponseWriter, r *http.Request) {
	h.handleSSELogs(w, r)
}

// ClearLogs clears all stored logs
func (h *Handlers) ClearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "DELETE" {
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	h.processMgr.ClearLogs()
	h.sendJSON(w, map[string]string{"status": "cleared"})
}

// SetLogLevel changes sing-box log level dynamically
func (h *Handlers) SetLogLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Level string `json:"level"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate log level
	validLevels := map[string]bool{
		"trace": true, "debug": true, "info": true,
		"warn": true, "error": true, "fatal": true, "panic": true,
	}
	if !validLevels[req.Level] {
		h.sendError(w, http.StatusBadRequest, "Invalid log level. Valid: trace, debug, info, warn, error, fatal, panic")
		return
	}

	// Update config
	cfg := h.cfgMgr.GetConfig()
	cfg.SingBox.LogLevel = req.Level
	if err := h.cfgMgr.UpdateConfig(cfg); err != nil {
		h.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Need to restart sing-box for log level to take effect
	h.sendJSON(w, map[string]interface{}{
		"status":  "updated",
		"level":   req.Level,
		"message": "Restart sing-box to apply new log level",
	})
}

// GetLogLevel returns current log level setting
func (h *Handlers) GetLogLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	cfg := h.cfgMgr.GetConfig()
	h.sendJSON(w, map[string]string{"level": cfg.SingBox.LogLevel})
}

// HandleLogLevel handles GET and POST for log level
func (h *Handlers) HandleLogLevel(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.GetLogLevel(w, r)
	case "POST":
		h.SetLogLevel(w, r)
	default:
		h.sendError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *Handlers) handleSSELogs(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Restrict CORS to localhost
	origin := r.Header.Get("Origin")
	if origin == "" || strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1") {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Subscribe to logs
	logChan := h.processMgr.SubscribeLogs()
	defer h.processMgr.UnsubscribeLogs(logChan)

	// Send existing logs first
	existingLogs := h.processMgr.GetLogs(100)
	for _, log := range existingLogs {
		data, err := json.Marshal(log)
		if err != nil {
			continue // Skip malformed entries
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
	}
	flusher.Flush()

	// Send new logs as they arrive
	ctx := r.Context()
	for {
		select {
		case log := <-logChan:
			data, err := json.Marshal(log)
			if err != nil {
				continue // Skip malformed entries
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

// Helper functions

func (h *Handlers) generateConfig() error {
	nodes := h.updater.GetNodes()
	cfg := h.cfgMgr.GetConfig()
	state := h.cfgMgr.GetState()

	sbConfig, err := h.generator.Generate(nodes, cfg, state)
	if err != nil {
		return err
	}

	return h.generator.SaveConfig(sbConfig, cfg.SingBox.ConfigPath)
}
