package mcp

import (
	"testing"

	"github.com/alex-ilgayev/mcpspy/pkg/ebpf"
)

func TestParseJSONRPC(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		data     []byte
		expected JSONRPCMessageType
		method   string
	}{
		{
			name:     "Request",
			data:     []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test"}}`),
			expected: JSONRPCMessageTypeRequest,
			method:   "tools/call",
		},
		{
			name:     "Response",
			data:     []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"OK"}]}}`),
			expected: JSONRPCMessageTypeResponse,
			method:   "",
		},
		{
			name:     "Notification",
			data:     []byte(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"value":50}}`),
			expected: JSONRPCMessageTypeNotification,
			method:   "notifications/progress",
		},
		{
			name:     "Error Response",
			data:     []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params"}}`),
			expected: JSONRPCMessageTypeResponse,
			method:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := parser.ParseData(tt.data, ebpf.EventTypeWrite, 1, "mcpspy")
			if err != nil {
				t.Fatalf("ParseData failed: %v", err)
			}

			if msg[0].Type != tt.expected {
				t.Errorf("Expected type %s, got %s", tt.expected, msg[0].Type)
			}

			if msg[0].Method != tt.method {
				t.Errorf("Expected method %s, got %s", tt.method, msg[0].Method)
			}
		})
	}
}

func TestParseStdioFraming(t *testing.T) {
	parser := NewParser()

	// Test stdio framing with Content-Length header
	data := []byte("Content-Length: 75\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"id\":0,\"params\":{\"version\":\"1.0.0\"}}")

	msg, err := parser.ParseData(data, ebpf.EventTypeWrite, 1, "mcpspy")
	if err != nil {
		t.Fatalf("ParseData failed: %v", err)
	}

	if msg[0].Type != JSONRPCMessageTypeRequest {
		t.Errorf("Expected request type, got %s", msg[0].Type)
	}

	if msg[0].Method != "initialize" {
		t.Errorf("Expected initialize method, got %s", msg[0].Method)
	}
}

func TestExtractToolName(t *testing.T) {
	msg := &Message{
		JSONRPCMessage: JSONRPCMessage{
			Method: "tools/call",
			Params: map[string]interface{}{
				"name": "web_scrape",
			},
		},
	}

	toolName := msg.ExtractToolName()
	if toolName != "web_scrape" {
		t.Errorf("Expected tool name 'web_scrape', got '%s'", toolName)
	}
}

func TestGetMethodInfo(t *testing.T) {
	tests := []struct {
		method   string
		expected string
	}{
		{"tools/call", "Execute a tool"},
		{"resources/read", "Read a resource"},
		{"initialize", "Initialize connection"},
		{"unknown/method", "Unknown method"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			info := GetMethodDescription(tt.method)
			if info != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, info)
			}
		})
	}
}

func TestParseData_RealWorldMessages(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		json     string
		typeWant JSONRPCMessageType
		method   string
		idSet    bool
	}{
		{
			name:     "Initialize request",
			json:     `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"version":"1.0.0"}}`,
			typeWant: JSONRPCMessageTypeRequest,
			method:   "initialize",
			idSet:    true,
		},
		{
			name:     "Tool call request",
			json:     `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","args":{"city":"London","units":"metric"}}}`,
			typeWant: JSONRPCMessageTypeRequest,
			method:   "tools/call",
			idSet:    true,
		},
		{
			name:     "Tool call response",
			json:     `{"jsonrpc":"2.0","id":2,"result":{"output":"Weather in London: Sunny, 22°C"}}`,
			typeWant: JSONRPCMessageTypeResponse,
			method:   "",
			idSet:    true,
		},
		{
			name:     "Resource read request",
			json:     `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"config://server"}}`,
			typeWant: JSONRPCMessageTypeRequest,
			method:   "resources/read",
			idSet:    true,
		},
		{
			name:     "Resource read response",
			json:     `{"jsonrpc":"2.0","id":3,"result":{"content":"{\"status\":\"healthy\"}"}}`,
			typeWant: JSONRPCMessageTypeResponse,
			method:   "",
			idSet:    true,
		},
		{
			name:     "Progress notification",
			json:     `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":0.5,"message":"Processing..."}}`,
			typeWant: JSONRPCMessageTypeNotification,
			method:   "notifications/progress",
			idSet:    false,
		},
		{
			name:     "Error response",
			json:     `{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"Invalid params"}}`,
			typeWant: JSONRPCMessageTypeResponse,
			method:   "",
			idSet:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs, err := parser.ParseData([]byte(tt.json), ebpf.EventTypeWrite, 1, "mcpspy")
			if err != nil {
				t.Fatalf("ParseData failed: %v", err)
			}
			if len(msgs) == 0 {
				t.Fatalf("No messages parsed")
			}
			msg := msgs[0]
			if msg.Type != tt.typeWant {
				t.Errorf("Expected type %s, got %s", tt.typeWant, msg.Type)
			}
			if msg.Method != tt.method {
				t.Errorf("Expected method %s, got %s", tt.method, msg.Method)
			}
			if tt.idSet && msg.ID == nil {
				t.Errorf("Expected ID to be set, got nil")
			}
			if !tt.idSet && msg.ID != nil {
				t.Errorf("Expected ID to be nil, got %v", msg.ID)
			}
		})
	}
}
