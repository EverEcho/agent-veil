package planner

import (
	"fmt"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

type Capability struct {
	Protocol           domain.Protocol
	RequestInspection  bool
	ResponseInspection bool
	StreamInspection   bool
	Observable         bool
}

type Options struct {
	Capabilities  map[domain.Protocol]Capability
	DefaultPolicy string
	Network       domain.NetworkRoute
}

func Build(manifest domain.AgentManifest, options Options) (domain.ProtectionPlan, error) {
	if err := manifest.Validate(); err != nil {
		return domain.ProtectionPlan{}, err
	}
	if options.DefaultPolicy == "" {
		return domain.ProtectionPlan{}, domain.NewError(domain.ErrInvalidContract, "build protection plan", "default policy id is required")
	}
	if err := options.Network.Validate(); err != nil {
		return domain.ProtectionPlan{}, err
	}
	for protocolType, capability := range options.Capabilities {
		if capability.Protocol != "" && capability.Protocol != protocolType {
			return domain.ProtectionPlan{}, domain.NewError(domain.ErrInvalidContract, "build protection plan", "capability protocol does not match its registry key")
		}
	}
	plan := domain.ProtectionPlan{SchemaVersion: manifest.SchemaVersion, ManifestID: manifest.Agent.ID}
	routeIDs := map[string]struct{}{}
	for _, surface := range manifest.Surfaces {
		coverage, route, risks := classify(surface, options)
		plan.Coverage = append(plan.Coverage, coverage)
		plan.Risks = append(plan.Risks, risks...)
		if route != nil {
			if _, exists := routeIDs[route.ID]; exists {
				return domain.ProtectionPlan{}, domain.NewError(domain.ErrInvalidContract, "build protection plan", "surface ids produce a duplicate protected route id")
			}
			routeIDs[route.ID] = struct{}{}
			plan.Routes = append(plan.Routes, *route)
		}
		addSummary(&plan.Summary, coverage.Status)
	}
	return plan, nil
}

func classify(surface domain.EgressSurface, options Options) (domain.SurfaceCoverage, *domain.ProtectedRoute, []domain.ProtectionRisk) {
	coverage := domain.SurfaceCoverage{SurfaceID: surface.ID}
	if surface.Type == domain.SurfaceMCPStdio && surface.Protocol == domain.ProtocolLocalStdio {
		coverage.Status, coverage.Reason = domain.CoverageLocal, "surface uses local stdio; descendant network egress is separate"
		return coverage, nil, nil
	}
	if surface.Type == domain.SurfaceUnknown || surface.Protocol == domain.ProtocolUnknown {
		coverage.Status, coverage.Reason = domain.CoverageUnprotected, "unknown surfaces and protocols fail closed"
		return coverage, nil, []domain.ProtectionRisk{{SurfaceID: surface.ID, Code: domain.RiskUnknownProtocol, Severity: domain.SeverityHigh, Message: coverage.Reason}}
	}
	capability, ok := options.Capabilities[surface.Protocol]
	if !ok {
		coverage.Status, coverage.Reason = domain.CoverageUnprotected, "no protocol capability is registered"
		return coverage, nil, []domain.ProtectionRisk{{SurfaceID: surface.ID, Code: domain.RiskUnsupportedCapability, Severity: domain.SeverityHigh, Message: coverage.Reason}}
	}
	if !surface.Rewritable {
		if capability.Observable {
			coverage.Status, coverage.Reason = domain.CoverageObserved, "traffic can be observed but the surface cannot be safely rewritten"
			return coverage, nil, []domain.ProtectionRisk{{SurfaceID: surface.ID, Code: domain.RiskObservedOnly, Severity: domain.SeverityHigh, Message: coverage.Reason}}
		}
		coverage.Status, coverage.Reason = domain.CoverageUnprotected, "surface cannot be safely rewritten"
		return coverage, nil, []domain.ProtectionRisk{{SurfaceID: surface.ID, Code: domain.RiskNotRewritable, Severity: domain.SeverityHigh, Message: coverage.Reason}}
	}
	if !capability.RequestInspection {
		coverage.Status, coverage.Reason = domain.CoverageObserved, "request content is not inspectable"
		return coverage, nil, []domain.ProtectionRisk{{SurfaceID: surface.ID, Code: domain.RiskObservedOnly, Severity: domain.SeverityHigh, Message: coverage.Reason}}
	}
	if !capability.ResponseInspection || !capability.StreamInspection {
		coverage.Status, coverage.Reason = domain.CoveragePartial, "request inspection is available but response or stream protection is incomplete"
		return coverage, nil, []domain.ProtectionRisk{{SurfaceID: surface.ID, Code: domain.RiskRequestOnly, Severity: domain.SeverityHigh, Message: coverage.Reason}}
	}
	routeID := "route-" + sanitizeID(surface.ID)
	coverage.Status, coverage.Reason, coverage.RouteID = domain.CoverageProtected, "request, response and stream inspection are available", routeID
	route := &domain.ProtectedRoute{ID: routeID, SurfaceID: surface.ID, Protocol: surface.Protocol,
		Upstream: *surface.Upstream, Auth: surface.Auth, Network: options.Network,
		PolicyID: options.DefaultPolicy, RequiresStream: true}
	return coverage, route, nil
}

func sanitizeID(value string) string {
	return strings.NewReplacer("/", "-", " ", "-", ":", "-").Replace(value)
}

func addSummary(summary *domain.CoverageSummary, status domain.CoverageStatus) {
	summary.Total++
	switch status {
	case domain.CoverageProtected:
		summary.Protected++
	case domain.CoverageLocal:
		summary.Local++
	case domain.CoveragePartial:
		summary.Partial++
	case domain.CoverageObserved:
		summary.Observed++
	case domain.CoverageUnprotected:
		summary.Unprotected++
	default:
		panic(fmt.Sprintf("invalid coverage status %q", status))
	}
}
