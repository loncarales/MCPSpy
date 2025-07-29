package userland

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"

	"github.com/alex-ilgayev/mcpspy/pkg/ebpf"
)

// Monitor represents the userland monitoring system
type Monitor struct {
	ctx      context.Context
	cancel   context.CancelFunc
	events   chan interface{}
	mu       sync.RWMutex
	running  bool
	logger   *logrus.Logger
	config   *Config
}

// Config holds configuration for userland monitoring
type Config struct {
	MonitorStdio   bool
	MonitorHTTP    bool
	MonitorSSL     bool
	MonitorPackets bool
	HTTPPort       string
	SSLPort        string
	Interface      string
	LogLevel       logrus.Level
}

// ProcessInfo holds information about monitored processes
type ProcessInfo struct {
	PID     int32
	Command string
	Args    []string
}

// New creates a new userland monitor
func New(config *Config) *Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	logger := logrus.New()
	logger.SetLevel(config.LogLevel)

	return &Monitor{
		ctx:    ctx,
		cancel: cancel,
		events: make(chan interface{}, 1000),
		logger: logger,
		config: config,
	}
}

// Start begins monitoring MCP communications
func (m *Monitor) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	var wg sync.WaitGroup

	// Start stdio monitoring if enabled
	if m.config.MonitorStdio {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.monitorStdio()
		}()
	}

	// Start HTTP monitoring if enabled
	if m.config.MonitorHTTP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.monitorHTTP()
		}()
	}

	// Start SSL monitoring if enabled
	if m.config.MonitorSSL {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.monitorSSL()
		}()
	}

	// Start packet monitoring if enabled
	if m.config.MonitorPackets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.monitorPackets()
		}()
	}

	// Wait for all monitoring goroutines to complete
	go func() {
		wg.Wait()
		close(m.events)
	}()

	return nil
}

// Stop stops the monitoring
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if !m.running {
		return
	}
	
	m.running = false
	m.cancel()
}

// Events returns the events channel
func (m *Monitor) Events() <-chan interface{} {
	return m.events
}

// monitorStdio monitors standard input/output for MCP communications
func (m *Monitor) monitorStdio() {
	m.logger.Info("Starting stdio monitoring...")
	
	// Monitor running processes for MCP-like communications
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.scanProcesses()
		}
	}
}

// scanProcesses scans for processes that might be using MCP
func (m *Monitor) scanProcesses() {
	// Get list of processes
	procDir, err := os.Open("/proc")
	if err != nil {
		m.logger.WithError(err).Debug("Failed to open /proc directory")
		return
	}
	defer procDir.Close()

	entries, err := procDir.Readdir(-1)
	if err != nil {
		m.logger.WithError(err).Debug("Failed to read /proc directory")
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is a PID
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		m.inspectProcess(int32(pid))
	}
}

// inspectProcess inspects a specific process for MCP activity
func (m *Monitor) inspectProcess(pid int32) {
	// Read process command line
	cmdlineFile := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineData, err := os.ReadFile(cmdlineFile)
	if err != nil {
		return
	}

	cmdline := string(cmdlineData)
	if cmdline == "" {
		return
	}

	// Split command line arguments (null-separated)
	args := strings.Split(strings.TrimRight(cmdline, "\x00"), "\x00")
	if len(args) == 0 {
		return
	}

	command := args[0]

	// Check if this looks like an MCP-related process
	if m.isMCPProcess(command, args) {
		m.monitorProcessPipes(pid, command, args)
	}
}

// isMCPProcess determines if a process might be using MCP
func (m *Monitor) isMCPProcess(command string, args []string) bool {
	// Look for common MCP indicators
	mcpIndicators := []string{
		"mcp",
		"claude",
		"anthropic",
		"model-context-protocol",
		"json-rpc",
	}

	fullCommand := strings.Join(args, " ")
	lowercaseCommand := strings.ToLower(fullCommand)

	for _, indicator := range mcpIndicators {
		if strings.Contains(lowercaseCommand, indicator) {
			return true
		}
	}

	// Check for Python/Node.js processes that might be MCP servers/clients
	if strings.Contains(command, "python") || strings.Contains(command, "node") {
		for _, arg := range args {
			if strings.Contains(strings.ToLower(arg), "mcp") {
				return true
			}
		}
	}

	return false
}

// monitorProcessPipes monitors pipes and file descriptors of a process
func (m *Monitor) monitorProcessPipes(pid int32, command string, args []string) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	
	// Try to read file descriptors
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		fdPath := fmt.Sprintf("%s/%s", fdDir, entry.Name())
		
		// Try to read the link to see what this FD points to
		link, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}

		// Check if this is a pipe or socket
		if strings.HasPrefix(link, "pipe:") || strings.HasPrefix(link, "socket:") {
			m.logger.WithFields(logrus.Fields{
				"pid":     pid,
				"command": command,
				"fd":      entry.Name(),
				"link":    link,
			}).Debug("Found potential MCP communication channel")

			// Try to read from the pipe/socket (this is a simplified approach)
			m.attemptPipeRead(fdPath, pid, command)
		}
	}
}

// attemptPipeRead attempts to read from a pipe for MCP data
func (m *Monitor) attemptPipeRead(fdPath string, pid int32, command string) {
	// This is a simplified approach - in a real implementation,
	// we'd need more sophisticated methods to intercept data
	
	// For now, we'll create a synthetic event to demonstrate the concept
	event := &ebpf.DataEvent{
		PID:       uint32(pid),
		EventType: ebpf.EventTypeRead,
		BufSize:   0,
	}
	
	// Copy command name
	copy(event.Buf[:], []byte(command))
	
	select {
	case m.events <- event:
	case <-m.ctx.Done():
	}
}

// monitorHTTP monitors HTTP traffic for MCP communications
func (m *Monitor) monitorHTTP() {
	m.logger.Info("Starting HTTP monitoring...")
	
	// Create a simple HTTP proxy/interceptor
	listener, err := net.Listen("tcp", ":"+m.config.HTTPPort)
	if err != nil {
		m.logger.WithError(err).Error("Failed to start HTTP listener")
		return
	}
	defer listener.Close()

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			
			go m.handleHTTPConnection(conn)
		}
	}
}

// handleHTTPConnection handles an HTTP connection
func (m *Monitor) handleHTTPConnection(conn net.Conn) {
	defer conn.Close()
	
	reader := bufio.NewReader(conn)
	
	// Read HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	
	// Read request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return
	}
	req.Body.Close()
	
	// Check if this looks like MCP JSON-RPC
	if m.isJSONRPC(body) {
		m.logger.WithFields(logrus.Fields{
			"method": req.Method,
			"url":    req.URL.String(),
			"body":   string(body),
		}).Info("Detected potential MCP HTTP communication")
		
		// Create event
		event := &ebpf.DataEvent{
			PID:       0, // Unknown PID for network traffic
			EventType: ebpf.EventTypeRead,
			BufSize:   uint32(len(body)),
		}
		copy(event.Buf[:], body)
		
		select {
		case m.events <- event:
		case <-m.ctx.Done():
		}
	}
}

// monitorSSL monitors SSL/TLS traffic for MCP communications
func (m *Monitor) monitorSSL() {
	m.logger.Info("Starting SSL monitoring...")
	
	// Create TLS listener
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		m.logger.WithError(err).Debug("Failed to load SSL certificates, skipping SSL monitoring")
		return
	}
	
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	
	listener, err := tls.Listen("tcp", ":"+m.config.SSLPort, config)
	if err != nil {
		m.logger.WithError(err).Error("Failed to start SSL listener")
		return
	}
	defer listener.Close()

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			
			go m.handleSSLConnection(conn)
		}
	}
}

// handleSSLConnection handles an SSL connection
func (m *Monitor) handleSSLConnection(conn net.Conn) {
	defer conn.Close()
	
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}
	
	data := buffer[:n]
	
	// Check if this looks like MCP JSON-RPC
	if m.isJSONRPC(data) {
		m.logger.WithField("data", string(data)).Info("Detected potential MCP SSL communication")
		
		// Create event
		event := &ebpf.DataEvent{
			PID:       0, // Unknown PID for network traffic
			EventType: ebpf.EventTypeRead,
			BufSize:   uint32(len(data)),
		}
		copy(event.Buf[:], data)
		
		select {
		case m.events <- event:
		case <-m.ctx.Done():
		}
	}
}

// monitorPackets monitors network packets for MCP communications
func (m *Monitor) monitorPackets() {
	m.logger.Info("Starting packet monitoring...")
	
	// Open packet capture
	handle, err := pcap.OpenLive(m.config.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		m.logger.WithError(err).Error("Failed to open packet capture")
		return
	}
	defer handle.Close()
	
	// Set filter for TCP traffic on common ports
	filter := "tcp and (port 80 or port 443 or port 8080 or port 3000)"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		m.logger.WithError(err).Error("Failed to set packet filter")
		return
	}
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	for {
		select {
		case <-m.ctx.Done():
			return
		case packet := <-packetSource.Packets():
			m.analyzePacket(packet)
		}
	}
}

// analyzePacket analyzes a network packet for MCP content
func (m *Monitor) analyzePacket(packet gopacket.Packet) {
	// Get TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	
	tcp, _ := tcpLayer.(*layers.TCP)
	payload := tcp.Payload
	
	if len(payload) == 0 {
		return
	}
	
	// Check if payload looks like JSON-RPC
	if m.isJSONRPC(payload) {
		m.logger.WithFields(logrus.Fields{
			"src_port": tcp.SrcPort,
			"dst_port": tcp.DstPort,
			"payload":  string(payload),
		}).Info("Detected potential MCP packet communication")
		
		// Create event
		event := &ebpf.DataEvent{
			PID:       0, // Unknown PID for network traffic
			EventType: ebpf.EventTypeRead,
			BufSize:   uint32(len(payload)),
		}
		copy(event.Buf[:], payload)
		
		select {
		case m.events <- event:
		case <-m.ctx.Done():
		}
	}
}

// isJSONRPC checks if data looks like JSON-RPC 2.0
func (m *Monitor) isJSONRPC(data []byte) bool {
	content := string(data)
	
	// Basic JSON-RPC 2.0 patterns
	jsonrpcPatterns := []string{
		`"jsonrpc":\s*"2\.0"`,
		`"method":\s*"[^"]*"`,
		`"id":\s*\d+`,
		`"result":\s*{`,
		`"error":\s*{`,
	}
	
	matchCount := 0
	for _, pattern := range jsonrpcPatterns {
		matched, _ := regexp.MatchString(pattern, content)
		if matched {
			matchCount++
		}
	}
	
	// Consider it JSON-RPC if it matches at least 2 patterns
	return matchCount >= 2
}

// AttachToProcess attaches to a running process (placeholder for ptrace implementation)
func (m *Monitor) AttachToProcess(pid int) error {
	// This would implement ptrace attachment to monitor system calls
	// For now, return not implemented
	return fmt.Errorf("process attachment not yet implemented")
}

// LaunchAndMonitor launches a command and monitors its MCP communications
func (m *Monitor) LaunchAndMonitor(command string, args []string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(m.ctx, command, args...)
	
	// Set up pipes to intercept stdout/stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	
	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}
	
	// Monitor stdout
	go m.monitorPipe(stdout, cmd.Process.Pid, "stdout")
	
	// Monitor stderr
	go m.monitorPipe(stderr, cmd.Process.Pid, "stderr")
	
	return cmd, nil
}

// monitorPipe monitors a pipe for MCP communications
func (m *Monitor) monitorPipe(pipe io.Reader, pid int, pipeType string) {
	scanner := bufio.NewScanner(pipe)
	
	for scanner.Scan() {
		line := scanner.Text()
		
		// Check if line contains JSON-RPC
		if m.isJSONRPC([]byte(line)) {
			m.logger.WithFields(logrus.Fields{
				"pid":       pid,
				"pipe_type": pipeType,
				"content":   line,
			}).Info("Detected MCP communication in pipe")
			
			// Create event
			event := &ebpf.DataEvent{
				PID:       uint32(pid),
				EventType: ebpf.EventTypeRead,
				BufSize:   uint32(len(line)),
			}
			copy(event.Buf[:], []byte(line))
			
			select {
			case m.events <- event:
			case <-m.ctx.Done():
				return
			}
		}
	}
}

// Close cleans up the monitor
func (m *Monitor) Close() error {
	m.Stop()
	return nil
}