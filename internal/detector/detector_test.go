package detector

import "testing"

func TestValidatedPIIAndSecrets(t *testing.T) {
	s := NewDefault()
	matches := s.Scan("/x", "mail dev@example.com phone 13800138000 id 11010519491231002X card 4111111111111111 ghp_abcdefghijklmnopqrstuvwxyz")
	if len(matches) != 5 {
		t.Fatalf("matches=%+v", matches)
	}
	if got := s.Scan("/x", "invalid card 4111111111111112 invalid id 110105194912310021"); len(got) != 0 {
		t.Fatalf("validators accepted invalid values: %+v", got)
	}
}
