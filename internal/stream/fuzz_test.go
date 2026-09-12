package stream

import "testing"

func FuzzSSEDecoderNeverEmitsIncompleteEvent(f *testing.F) {
	f.Add([]byte("data: ok\n\n"))
	f.Add([]byte("data: incomplete"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 4096 {
			return
		}
		decoder, _ := NewDecoder(4096)
		_, _ = decoder.Push(input)
		_ = decoder.Close()
	})
}
