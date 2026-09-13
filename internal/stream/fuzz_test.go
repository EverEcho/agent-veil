package stream

import (
	"reflect"
	"testing"
)

func FuzzSSEDecoderChunkingInvariant(f *testing.F) {
	f.Add([]byte("data: ok\n\n"))
	f.Add([]byte("data: incomplete"))
	f.Add([]byte("data: cr\r\rdata: mixed\r\n\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			return
		}
		whole, _ := NewDecoder(4096)
		wholeEvents, wholePushErr := whole.Push(input)
		wholeCloseErr := whole.Close()

		chunked, _ := NewDecoder(4096)
		var chunkedEvents []Event
		var chunkedPushErr error
		for _, value := range input {
			events, err := chunked.Push([]byte{value})
			chunkedEvents = append(chunkedEvents, events...)
			if err != nil {
				chunkedPushErr = err
				break
			}
		}
		chunkedCloseErr := chunked.Close()
		if (wholePushErr != nil) != (chunkedPushErr != nil) || (wholeCloseErr != nil) != (chunkedCloseErr != nil) || !reflect.DeepEqual(wholeEvents, chunkedEvents) {
			t.Fatalf("decoder result changed across chunking: whole=%+v push=%v close=%v chunked=%+v push=%v close=%v", wholeEvents, wholePushErr, wholeCloseErr, chunkedEvents, chunkedPushErr, chunkedCloseErr)
		}
	})
}
