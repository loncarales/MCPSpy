package output

import (
	"github.com/alex-ilgayev/mcpspy/pkg/mcp"
)

// OutputHandler defines the interface for different output formats
type OutputHandler interface {
	PrintHeader()
	PrintStats(stats map[string]int)
	PrintInfo(format string, args ...interface{})
	PrintMessages(messages []*mcp.Message)
}
