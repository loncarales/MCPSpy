package debug

import (
	"bufio"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

func PrintTracePipe(log *logrus.Logger) error {
	p, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		return err
	}
	defer p.Close()

	scanner := bufio.NewScanner(p)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		log.WithField("type", "kernel_event_t").Debug(strings.TrimSpace(scanner.Text()))
	}

	return nil
}
