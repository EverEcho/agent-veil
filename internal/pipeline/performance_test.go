package pipeline

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/redactor"
)

const pureRuleP95Budget = 15 * time.Millisecond

func TestPureRulePipelineP95Budget(t *testing.T) {
	if os.Getenv("VEIL_PERFORMANCE_GATE") != "1" {
		t.Skip("set VEIL_PERFORMANCE_GATE=1 to run the hardware-sensitive performance gate")
	}
	const samples = 500
	body := []byte(`{"input":"` + strings.Repeat("ordinary local agent context ", 1024) + ` contact dev@example.com or 13800138000","model":"local-benchmark"}`)
	scanner := detector.NewDefault()
	engine := policy.Engine{Default: domain.ActionRedact}
	durations := make([]time.Duration, 0, samples)
	for iteration := 0; iteration < samples+25; iteration++ {
		started := time.Now()
		vault, err := redactor.NewVault([]byte(strings.Repeat("p", 32)), redactor.Limits{MaxEntries: 16, MaxOriginalBytes: 4096})
		if err != nil {
			t.Fatal(err)
		}
		result, err := ProcessForProtocol(Context{AgentID: "benchmark", SurfaceID: "primary"}, domain.ProtocolOpenAIResponses, "/v1/responses", "application/json", "", body, scanner, engine, vault)
		elapsed := time.Since(started)
		vault.Destroy()
		if err != nil || len(result.Findings) != 2 || strings.Contains(string(result.Body), "dev@example.com") || strings.Contains(string(result.Body), "13800138000") {
			t.Fatalf("pure-rule pipeline result is invalid: findings=%d err=%v", len(result.Findings), err)
		}
		if iteration >= 25 {
			durations = append(durations, elapsed)
		}
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(len(durations)*95+99)/100-1]
	t.Logf("pure-rule local pipeline P95=%s over %d samples (%d-byte request)", p95, len(durations), len(body))
	if p95 >= pureRuleP95Budget {
		t.Fatalf("pure-rule local pipeline P95 %s exceeds %s product budget", p95, pureRuleP95Budget)
	}
}
