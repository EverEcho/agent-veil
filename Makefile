.PHONY: test verify acceptance-evidence build

test:
	go test ./...

verify:
	go vet ./...
	go test -race ./...

# Replays the repository-owned evidence cited by doc/08-acceptance-evidence.md.
# This target proves only the automated scope; it intentionally does not stand
# in for real-application or target-platform validation.
acceptance-evidence:
	go test ./internal/protocol -run '^(TestProtocolFixturesExtractOnlyBusinessContentAndRoundTrip|TestLegacyMCPSSECannotBorrowImplementedMCPAdapters)$$' -count=1
	go test ./internal/planner -run '^TestLegacyMCPSSEIsKnownButUnprotectedWithoutTransportCapability$$' -count=1
	go test ./internal/pipeline -run '^(TestNonStreamingResponseProtocolMatrixRestoresPlaceholders|TestSSEProtocolMatrixRestoresFragmentedPlaceholders|TestSSEProtocolMatrixBlocksNewCredentials)$$' -count=1
	go test ./internal/proxy -run '^(TestEndToEndProtocolMatrixOnlySendsRedactedContentToProvider|TestMCPRoutesUseExactConfiguredUpstreamPath)$$' -count=1
	go test ./internal/registry -run '^(TestIntegrationLeaseExpiresAndRejectsStaleGeneration|TestRegistryQueuesRoutesForEveryActiveGenerationInvalidation|TestRegistryRevocationQueueFailsClosedWhenBoundExceeded)$$' -count=1
	go test ./internal/discovery -run '^(TestUnverifiedProtectedAgentsReturnRiskOnlyManifests|TestAutomaticDiscoveryReportsUnknownVersionsWithoutClaimingCompatibility)$$' -count=1
	go test ./internal/core -run '^TestInspectionPreviewReturnsManifestAndTruthfulCoverage$$' -count=1
	go test ./cmd/veil -run '^TestInspectionIncludesManifestAndTruthfulPlan$$' -count=1
	go test ./internal/routing -run '^TestContentModifierAfterDLPIsBlocked$$' -count=1
	go test ./internal/audit ./internal/diagnostic -count=1
	go test ./internal/compatibility -run '^TestMatrixIsExplicitAndPlatformScoped$$' -count=1

build:
	go build -trimpath -o veil ./cmd/veil
