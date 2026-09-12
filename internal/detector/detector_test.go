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

func TestCaptureGroupPreservesAssignmentContext(t *testing.T) {
	matches := NewDefault().Scan("/x", "Authorization stays; API_KEY=Abcdef123456!xyz")
	if len(matches) != 1 || matches[0].Value != "Abcdef123456!xyz" {
		t.Fatalf("capture=%+v", matches)
	}
}

func TestProviderSecretFamilies(t *testing.T) {
	text := "AKIAABCDEFGHIJKLMNOP xoxb-1234567890-abcdefghijklmnop glpat-abcdefghijklmnopqrst sk_live_abcdefghijklmnopqrst eyJabcdef.abcdefgh.abcdefgh"
	if matches := NewDefault().Scan("/x", text); len(matches) != 5 {
		t.Fatalf("matches=%+v", matches)
	}
}

func TestStructuredChineseValidators(t *testing.T) {
	scanner := NewDefault()
	valid := scanner.Scan("/x", "id 11010519491231002X uscc 91350211M000100Y46 tel 010-12345678")
	if len(valid) != 3 {
		t.Fatalf("valid=%+v", valid)
	}
	invalid := scanner.Scan("/x", "id 99010519490231002X uscc 91350211M000100Y44")
	if len(invalid) != 0 {
		t.Fatalf("invalid accepted=%+v", invalid)
	}
}
