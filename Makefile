.PHONY: test verify acceptance-evidence build desktop-test desktop-build-ci package-dev

test:
	go test ./...

verify:
	go vet ./...
	go test -race ./...

# Replays the repository-owned evidence cited by doc/08-acceptance-evidence.md.
# This target proves only the automated scope; it intentionally does not stand
# in for real-application or target-platform validation.
acceptance-evidence:
	go test ./internal/protocol -run '^(TestProtocolFixturesExtractOnlyBusinessContentAndRoundTrip|TestLegacyMCPSSEUsesStrictMCPEnvelopes|TestContentProtectedProtocolsExcludeUnimplementedTransports)$$' -count=1
	go test ./internal/integration -run '^(TestResetHermesLaunchRootRemovesBoundedOwnedResidue|TestResetHermesLaunchRootNeverClaimsOrDeletesUnknownData|TestRewriteHermesLegacySSEPreservesTransportAndPinsCapability|TestHermesLegacyMCPSSEIsBoundToStatefulAdapter)$$' -count=1
	go test ./internal/planner -run '^TestLegacyMCPSSEIsKnownButUnprotectedWithoutTransportCapability$$' -count=1
	go test ./internal/pipeline -run '^(TestNonStreamingResponseProtocolMatrixRestoresPlaceholders|TestSSEProtocolMatrixRestoresFragmentedPlaceholders|TestSSEProtocolMatrixBlocksNewCredentials)$$' -count=1
	go test ./internal/proxy -run '^(TestEndToEndProtocolMatrixOnlySendsRedactedContentToProvider|TestMCPRoutesUseExactConfiguredUpstreamPath|TestLegacySSEManagerBindsExactCapabilityAndOwnsVault|TestLegacySSEManagerIsBoundedAndRevocationFailsClosed|TestLegacySSEManagerGracefulCloseDrainsAcquiredPost|TestLegacyMCPSSEDualEndpointRoundTripProtectsProviderBoundary|TestLegacyMCPSSERejectsCrossOriginAdvertisedEndpoint)$$' -count=1
	go test ./internal/registry -run '^(TestIntegrationLeaseExpiresAndRejectsStaleGeneration|TestRegistryQueuesRoutesForEveryActiveGenerationInvalidation|TestRegistryRevocationQueueFailsClosedWhenBoundExceeded)$$' -count=1
	go test ./internal/instance -run '^(TestOperatingSystemReleasesCoreLockAfterCrash|TestCoreStateRoundTripAndPermissions)$$' -count=1
	go test ./internal/discovery -run '^(TestUnverifiedProtectedAgentsReturnRiskOnlyManifests|TestAutomaticDiscoveryReportsUnknownVersionsWithoutClaimingCompatibility)$$' -count=1
	go test ./internal/core -run '^(TestInspectionPreviewReturnsManifestAndTruthfulCoverage|TestCoreKeepsLegacyMCPSSEStateAcrossPerRequestHandlers)$$' -count=1
	go test ./cmd/veil -run '^(TestInspectionIncludesManifestAndTruthfulPlan|TestResolveCoreEndpointRejectsStaleIdentityWithoutSendingAdminToken|TestServeClearsCrashedCoreStateBeforeLaterStartupFailure)$$' -count=1
	go test ./internal/routing -run '^TestContentModifierAfterDLPIsBlocked$$' -count=1
	go test ./internal/audit ./internal/diagnostic -count=1
	go test ./internal/compatibility -run '^(TestMatrixIsExplicitAndPlatformScoped|TestValidationRejectsUnsupportedProtectedProtocol)$$' -count=1
	go test ./sdk/attach -run '^TestControllerAttachesRotatesAndRestores$$' -count=1
	go test ./internal/desktopapp -run '^(TestSupervisorAdoptsButDoesNotStopExternalCore|TestAutoStartWritesAndRemovesPlatformEntries|TestDesktopTokenPersistsPrivately)$$' -count=1

build:
	go build -trimpath -o veil ./cmd/veil

desktop-test:
	go test ./internal/desktopapp

desktop-build-ci:
	cargo check --locked --manifest-path desktop/src-tauri/Cargo.toml

# Local, fast development package. CI produces the complete multi-platform bundle.
package-dev:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test ./internal/core ./internal/proxy ./internal/session ./internal/desktopapp ./sdk/attach
	mkdir -p dist/dev
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o dist/dev/veil ./cmd/veil
	cargo build --release --locked --manifest-path desktop/src-tauri/Cargo.toml
	cp desktop/src-tauri/target/release/agentveil-desktop dist/dev/agentveil-desktop
