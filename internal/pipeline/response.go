package pipeline

import (
	"context"
	"sort"

	"github.com/agentveil/agentveil/internal/detector"
	"github.com/agentveil/agentveil/internal/domain"
	"github.com/agentveil/agentveil/internal/policy"
	"github.com/agentveil/agentveil/internal/protocol"
	"github.com/agentveil/agentveil/internal/redactor"
)

type ResponseResult struct {
	Body     []byte
	Findings []domain.Finding
	Actions  []domain.Action
}

func ProcessResponse(protocolType domain.Protocol, contentType string, body []byte, scanner detector.ContentScanner, vault *redactor.Vault) ([]byte, error) {
	result, err := ProcessResponseDetailed(protocolType, contentType, body, scanner, vault)
	return result.Body, err
}

func ProcessResponseDetailed(protocolType domain.Protocol, contentType string, body []byte, scanner detector.ContentScanner, vault *redactor.Vault) (ResponseResult, error) {
	return ProcessResponseDetailedWithPolicy(Context{}, protocolType, contentType, body, scanner, policy.Engine{Default: domain.ActionBlock}, vault)
}

func ProcessResponseDetailedWithPolicy(ctx Context, protocolType domain.Protocol, contentType string, body []byte, scanner detector.ContentScanner, engine policy.Engine, vault *redactor.Vault) (ResponseResult, error) {
	var result ResponseResult
	document, err := protocol.ParseResponse(protocolType, contentType, body)
	if err != nil {
		return result, err
	}
	replacements := map[string]string{}
	for _, field := range document.Fields {
		matches, scanErr := detector.ScanContent(scanner, field.Path, field.Text)
		if scanErr != nil {
			return result, scanErr
		}
		text := field.Text
		sort.Slice(matches, func(i, j int) bool { return matches[i].Finding.Location.Start > matches[j].Finding.Location.Start })
		for _, match := range matches {
			action, actionErr := decideResponseAction(ctx, engine, match.Finding)
			if actionErr != nil {
				return result, actionErr
			}
			result.Findings = append(result.Findings, match.Finding)
			result.Actions = append(result.Actions, action)
			switch action {
			case domain.ActionBlock:
				return result, domain.NewError(domain.ErrPolicyBlocked, "process response", "policy blocked provider response content")
			case domain.ActionRedact:
				start, end := match.Finding.Location.Start, match.Finding.Location.End
				text = text[:start] + "[REDACTED]" + text[end:]
			}
		}
		restored, restoreErr := vault.Restore(text)
		if restoreErr != nil {
			return result, restoreErr
		}
		if restored != field.Text {
			replacements[field.Path] = restored
		}
	}
	result.Body, err = document.Replace(replacements)
	return result, err
}

func decideResponseAction(ctx Context, engine policy.Engine, finding domain.Finding) (domain.Action, error) {
	decision, err := engine.Decide(policy.Scope{AgentID: ctx.AgentID, Workspace: ctx.Workspace, Provider: ctx.Provider, SurfaceID: ctx.SurfaceID, FindingType: finding.Category}, ctx.Interactive)
	if err != nil {
		return "", err
	}
	action := decision.Action
	if action != domain.ActionAsk {
		return action, nil
	}
	if !ctx.Interactive || ctx.Approver == nil {
		return "", domain.NewError(domain.ErrInteractionRequired, "process response", "interactive policy decision is required")
	}
	requestContext := ctx.RequestContext
	if requestContext == nil {
		requestContext = context.Background()
	}
	return ctx.Approver.Request(requestContext, finding)
}
