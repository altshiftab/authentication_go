// Package log_options_testing captures the lines an endpoint logs, through the logger the services
// log through, for the endpoints' tests of what their audit lines say.
package log_options_testing

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"sync"

	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftContextLogger "github.com/altshiftab/utils_go/pkg/log/context_logger"
)

// lockedBuffer is the buffer Capture writes into: a handler under test may log from an HTTP server's
// goroutine while the test reads.
type lockedBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) Bytes() []byte {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}

// Capture runs run with the default logger writing JSON lines into memory, and returns the lines
// written meanwhile. The logger is utils_go's context logger, as the services build it, so that the
// lines are what a service's would be: same-named groups merged, and an error the context carries
// written out.
//
// It swaps the process-wide default logger, so call it only from a test that is not parallel, and
// from subtests that are not either.
func Capture(run func()) ([]map[string]any, error) {
	buffer := &lockedBuffer{}

	// The log package is restored by hand: SetDefault leaves its output alone when given a logger on
	// slog's own default handler, so restoring such a logger would leave log writing into the buffer.
	previous := slog.Default()
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	defer func() {
		slog.SetDefault(previous)
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	}()

	httpContextExtractor := http_context_extractor.New()
	slog.SetDefault(
		altshiftContextLogger.New(
			slog.NewJSONHandler(buffer, &slog.HandlerOptions{Level: slog.LevelDebug}),
			&altshiftLog.ErrorContextExtractor{ContextExtractors: []altshiftLog.ContextExtractor{httpContextExtractor}},
			httpContextExtractor,
		),
	)

	run()

	var lines []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(buffer.Bytes()))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var line map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			return nil, fmt.Errorf("json unmarshal (log line): %w", err)
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner: %w", err)
	}

	return lines, nil
}

// Events returns the event groups of the lines whose event.action is action, in order.
func Events(lines []map[string]any, action string) []map[string]any {
	var events []map[string]any
	for _, line := range lines {
		event, ok := line["event"].(map[string]any)
		if !ok {
			continue
		}
		if lineAction, _ := event["action"].(string); lineAction == action {
			events = append(events, event)
		}
	}

	return events
}
