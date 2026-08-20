package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// Progress is a single line of live counters, rewritten in place.
//
// It writes to standard error and only when that is a terminal, so piping
// bond's output somewhere gives clean text and a cron job's mail is not full
// of carriage returns.
type Progress struct {
	w        io.Writer
	enabled  bool
	interval time.Duration

	mu       sync.Mutex
	items    int
	bytes    int64
	started  time.Time
	lastDraw time.Time
	width    int
}

// NewProgress starts a counter on w.
func NewProgress(w io.Writer) *Progress {
	enabled := false
	if f, ok := w.(*os.File); ok {
		enabled = term.IsTerminal(int(f.Fd()))
	}
	return &Progress{
		w:        w,
		enabled:  enabled,
		interval: 200 * time.Millisecond,
		started:  time.Now(),
	}
}

// Add records one more item of n bytes.
func (p *Progress) Add(n int64) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.items++
	p.bytes += n
	if !p.enabled || time.Since(p.lastDraw) < p.interval {
		return
	}
	p.lastDraw = time.Now()
	p.draw()
}

func (p *Progress) draw() {
	elapsed := time.Since(p.started)
	line := fmt.Sprintf("    %s, %s", Items(p.items, "item", "items"), Bytes(p.bytes))
	if secs := elapsed.Seconds(); secs > 1 {
		line += fmt.Sprintf(", %s/s", Bytes(int64(float64(p.bytes)/secs)))
	}
	if len(line) < p.width {
		line += strings.Repeat(" ", p.width-len(line))
	}
	p.width = len(line)
	fmt.Fprintf(p.w, "\r%s", line)
}

// Clear removes the counter line so ordinary output can be printed.
func (p *Progress) Clear() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled || p.width == 0 {
		return
	}
	fmt.Fprintf(p.w, "\r%s\r", strings.Repeat(" ", p.width))
	p.width = 0
}
