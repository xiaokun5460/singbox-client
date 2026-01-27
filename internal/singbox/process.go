package singbox

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Constants
const (
	DefaultMaxLogs     = 1000
	LogChannelBuffer   = 100
	StopTimeout        = 10 * time.Second
	RestartDelay       = 500 * time.Millisecond
)

type ProcessState int

const (
	StateStopped ProcessState = iota
	StateStarting
	StateRunning
	StateStopping
)

func (s ProcessState) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	default:
		return "unknown"
	}
}

type ProcessManager struct {
	mu          sync.RWMutex
	cmd         *exec.Cmd
	cancel      context.CancelFunc
	state       ProcessState
	binaryPath  string
	configPath  string
	logs        []LogEntry
	maxLogs     int
	logChan     chan LogEntry
	listeners   []chan LogEntry
	lastLogMsg  string // For deduplication
}

type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

type Status struct {
	State     string    `json:"state"`
	StartTime time.Time `json:"start_time,omitempty"`
	Uptime    string    `json:"uptime,omitempty"`
	PID       int       `json:"pid,omitempty"`
}

var (
	instance *ProcessManager
	once     sync.Once
)

func GetProcessManager() *ProcessManager {
	once.Do(func() {
		instance = &ProcessManager{
			state:   StateStopped,
			logs:    make([]LogEntry, 0, DefaultMaxLogs),
			maxLogs: DefaultMaxLogs,
			logChan: make(chan LogEntry, LogChannelBuffer),
		}
		go instance.logDistributor()
	})
	return instance
}

func (pm *ProcessManager) Initialize(binaryPath, configPath string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.binaryPath = binaryPath
	pm.configPath = configPath
}

func (pm *ProcessManager) Start() error {
	pm.mu.Lock()
	if pm.state == StateRunning || pm.state == StateStarting {
		pm.mu.Unlock()
		return fmt.Errorf("sing-box is already running or starting")
	}
	pm.state = StateStarting
	pm.mu.Unlock()

	// Check if binary exists
	if _, err := os.Stat(pm.binaryPath); os.IsNotExist(err) {
		pm.mu.Lock()
		pm.state = StateStopped
		pm.mu.Unlock()
		return fmt.Errorf("sing-box binary not found at %s", pm.binaryPath)
	}

	// Check if config exists
	if _, err := os.Stat(pm.configPath); os.IsNotExist(err) {
		pm.mu.Lock()
		pm.state = StateStopped
		pm.mu.Unlock()
		return fmt.Errorf("sing-box config not found at %s", pm.configPath)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, pm.binaryPath, "run", "-c", pm.configPath)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		pm.mu.Lock()
		pm.state = StateStopped
		pm.mu.Unlock()
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		pm.mu.Lock()
		pm.state = StateStopped
		pm.mu.Unlock()
		return fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		pm.mu.Lock()
		pm.state = StateStopped
		pm.mu.Unlock()
		return fmt.Errorf("failed to start sing-box: %w", err)
	}

	pm.mu.Lock()
	pm.cmd = cmd
	pm.cancel = cancel
	pm.state = StateRunning
	pm.mu.Unlock()

	// Read stdout
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			pm.addLog("info", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			pm.addLog("error", fmt.Sprintf("stdout read error: %v", err))
		}
	}()

	// Read stderr (sing-box outputs all logs to stderr)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			level := parseLogLevel(line)
			pm.addLog(level, line)
		}
		if err := scanner.Err(); err != nil {
			pm.addLog("error", fmt.Sprintf("stderr read error: %v", err))
		}
	}()

	// Monitor process
	go func() {
		err := cmd.Wait()
		pm.mu.Lock()
		pm.state = StateStopped
		pm.cmd = nil
		pm.cancel = nil
		pm.mu.Unlock()
		if err != nil {
			pm.addLog("error", fmt.Sprintf("sing-box exited: %v", err))
		} else {
			pm.addLog("info", "sing-box stopped")
		}
	}()

	pm.addLog("info", "sing-box started")
	return nil
}

func (pm *ProcessManager) Stop() error {
	pm.mu.Lock()
	if pm.state != StateRunning {
		pm.mu.Unlock()
		return fmt.Errorf("sing-box is not running")
	}
	pm.state = StateStopping
	cancel := pm.cancel
	pm.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	// Wait for process to stop with timeout
	timeout := time.After(StopTimeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for sing-box to stop")
		case <-ticker.C:
			pm.mu.RLock()
			state := pm.state
			pm.mu.RUnlock()
			if state == StateStopped {
				return nil
			}
		}
	}
}

func (pm *ProcessManager) Restart() error {
	pm.mu.RLock()
	state := pm.state
	pm.mu.RUnlock()

	if state == StateRunning {
		if err := pm.Stop(); err != nil {
			return err
		}
	}

	// Wait a bit before starting
	time.Sleep(RestartDelay)

	return pm.Start()
}

func (pm *ProcessManager) GetStatus() Status {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	status := Status{
		State: pm.state.String(),
	}

	if pm.cmd != nil && pm.cmd.Process != nil {
		status.PID = pm.cmd.Process.Pid
	}

	return status
}

func (pm *ProcessManager) GetState() ProcessState {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.state
}

func (pm *ProcessManager) addLog(level, message string) {
	// Clean the message
	message = cleanLogMessage(message)
	if message == "" {
		return
	}

	// Deduplicate consecutive identical messages
	pm.mu.Lock()
	if message == pm.lastLogMsg {
		pm.mu.Unlock()
		return
	}
	pm.lastLogMsg = message

	entry := LogEntry{
		Time:    time.Now(),
		Level:   level,
		Message: message,
	}

	pm.logs = append(pm.logs, entry)
	if len(pm.logs) > pm.maxLogs {
		pm.logs = pm.logs[len(pm.logs)-pm.maxLogs:]
	}
	pm.mu.Unlock()

	select {
	case pm.logChan <- entry:
	default:
		// Drop log if channel is full
	}
}

func (pm *ProcessManager) GetLogs(limit int) []LogEntry {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if limit <= 0 || limit > len(pm.logs) {
		limit = len(pm.logs)
	}

	start := len(pm.logs) - limit
	result := make([]LogEntry, limit)
	copy(result, pm.logs[start:])
	return result
}

// ClearLogs clears all stored logs
func (pm *ProcessManager) ClearLogs() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.logs = make([]LogEntry, 0)
	pm.lastLogMsg = ""
}

func (pm *ProcessManager) SubscribeLogs() chan LogEntry {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	ch := make(chan LogEntry, 100)
	pm.listeners = append(pm.listeners, ch)
	return ch
}

func (pm *ProcessManager) UnsubscribeLogs(ch chan LogEntry) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i, listener := range pm.listeners {
		if listener == ch {
			pm.listeners = append(pm.listeners[:i], pm.listeners[i+1:]...)
			close(ch)
			break
		}
	}
}

func (pm *ProcessManager) logDistributor() {
	for entry := range pm.logChan {
		pm.mu.RLock()
		listeners := make([]chan LogEntry, len(pm.listeners))
		copy(listeners, pm.listeners)
		pm.mu.RUnlock()

		for _, ch := range listeners {
			select {
			case ch <- entry:
			default:
				// Drop if listener is slow
			}
		}
	}
}

func (pm *ProcessManager) CheckBinary() (bool, string) {
	if _, err := os.Stat(pm.binaryPath); os.IsNotExist(err) {
		return false, ""
	}

	cmd := exec.Command(pm.binaryPath, "version")
	output, err := cmd.Output()
	if err != nil {
		return true, "unknown"
	}

	return true, string(output)
}

// parseLogLevel extracts log level from sing-box log line
func parseLogLevel(line string) string {
	lineLower := strings.ToLower(line)
	switch {
	case strings.Contains(lineLower, "fatal"):
		return "fatal"
	case strings.Contains(lineLower, "error"):
		return "error"
	case strings.Contains(lineLower, "warn"):
		return "warn"
	case strings.Contains(lineLower, "debug"):
		return "debug"
	case strings.Contains(lineLower, "trace"):
		return "trace"
	default:
		return "info"
	}
}

// ANSI escape code regex
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// cleanLogMessage removes ANSI codes and simplifies sing-box log format
func cleanLogMessage(line string) string {
	// Remove ANSI escape codes
	line = ansiRegex.ReplaceAllString(line, "")

	// Remove timestamp prefix like "+0800 2026-01-27 11:50:29 "
	// Format: +ZZZZ YYYY-MM-DD HH:MM:SS (at least 25 chars)
	if len(line) > 25 && line[0] == '+' {
		// Find space after time portion
		if idx := strings.Index(line[20:], " "); idx != -1 && 20+idx+1 < len(line) {
			line = line[20+idx+1:]
		}
	}

	// Remove connection ID like "[260670903 0ms] "
	// Format: LEVEL [ID Xms] message
	if strings.HasPrefix(line, "INFO ") || strings.HasPrefix(line, "WARN ") || strings.HasPrefix(line, "ERROR ") {
		if start := strings.Index(line, "["); start != -1 {
			if end := strings.Index(line[start:], "] "); end != -1 {
				newEnd := start + end + 2
				if newEnd <= len(line) {
					line = line[:start] + line[newEnd:]
				}
			}
		}
	}

	return strings.TrimSpace(line)
}
