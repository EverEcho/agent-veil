package stream

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

type Event struct {
	ID    string
	Event string
	Data  string
	Retry string
}

func Encode(events []Event) []byte {
	var output strings.Builder
	for _, event := range events {
		if event.ID != "" {
			fmt.Fprintf(&output, "id: %s\n", event.ID)
		}
		if event.Event != "" {
			fmt.Fprintf(&output, "event: %s\n", event.Event)
		}
		if event.Retry != "" {
			fmt.Fprintf(&output, "retry: %s\n", event.Retry)
		}
		for _, line := range strings.Split(event.Data, "\n") {
			if event.Data != "" {
				fmt.Fprintf(&output, "data: %s\n", line)
			}
		}
		output.WriteByte('\n')
	}
	return []byte(output.String())
}

type Decoder struct {
	buffer   []byte
	maxEvent int
}

func NewDecoder(maxEventBytes int) (*Decoder, error) {
	if maxEventBytes <= 0 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create SSE decoder", "positive event limit is required")
	}
	return &Decoder{maxEvent: maxEventBytes}, nil
}

func (d *Decoder) Push(chunk []byte) ([]Event, error) {
	d.buffer = append(d.buffer, chunk...)
	if len(d.buffer) > d.maxEvent {
		return nil, domain.NewError(domain.ErrInvalidContract, "decode SSE", "event buffer limit exceeded")
	}
	var events []Event
	for {
		index, width := eventBoundary(d.buffer)
		if index < 0 {
			break
		}
		raw := append([]byte(nil), d.buffer[:index]...)
		d.buffer = append(d.buffer[:0], d.buffer[index+width:]...)
		events = append(events, parseEvent(raw))
	}
	return events, nil
}

func (d *Decoder) Close() error {
	if len(bytes.TrimSpace(d.buffer)) != 0 {
		return domain.NewError(domain.ErrInvalidContract, "decode SSE", "stream ended with an incomplete event")
	}
	d.buffer = nil
	return nil
}

func eventBoundary(data []byte) (int, int) {
	if index := bytes.Index(data, []byte("\n\n")); index >= 0 {
		return index, 2
	}
	if index := bytes.Index(data, []byte("\r\n\r\n")); index >= 0 {
		return index, 4
	}
	return -1, 0
}

func parseEvent(raw []byte) Event {
	var event Event
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimPrefix(value, " ")
		switch key {
		case "id":
			event.ID = value
		case "event":
			event.Event = value
		case "retry":
			event.Retry = value
		case "data":
			if event.Data != "" {
				event.Data += "\n"
			}
			event.Data += value
		}
	}
	return event
}
