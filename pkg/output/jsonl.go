package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/alex-ilgayev/mcpspy/pkg/mcp"
	"github.com/sirupsen/logrus"
)

// JSONLDisplay handles JSONL output formatting
type JSONLDisplay struct {
	writer io.Writer
}

// NewJSONLDisplay creates a new display handler for JSONL output with custom writer
func NewJSONLDisplay(writer io.Writer) *JSONLDisplay {
	return &JSONLDisplay{
		writer: writer,
	}
}

// PrintHeader does nothing for JSONL output (no header needed)
func (j *JSONLDisplay) PrintHeader() {
	// No header for JSONL output
}

// PrintStats does nothing for JSONL output (stats not applicable)
func (j *JSONLDisplay) PrintStats(stats map[string]int) {
	// No stats output for JSONL format
}

// PrintInfo does nothing for JSONL output (info messages not applicable)
func (j *JSONLDisplay) PrintInfo(format string, args ...interface{}) {
	// No info messages for JSONL format
}

// PrintMessages outputs messages in JSONL format
func (j *JSONLDisplay) PrintMessages(messages []*mcp.Message) {
	for _, msg := range messages {
		j.printMessage(msg)
	}
}

// printMessage outputs a single message in JSON format
func (j *JSONLDisplay) printMessage(msg *mcp.Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal message")
		return
	}

	fmt.Fprintf(j.writer, "%s\n", string(data))
}
