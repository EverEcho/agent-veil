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

type Context struct {
	AgentID, Workspace, Provider, SurfaceID string
	Interactive                             bool
	RequestContext                          context.Context
	Approver                                interface {
		Request(context.Context, domain.Finding) (domain.Action, error)
	}
}
type Result struct {
	Body     []byte
	Protocol domain.Protocol
	Findings []domain.Finding
	Actions  []domain.Action
	Vault    *redactor.Vault
}

type TextResult struct {
	Text     string
	Findings []domain.Finding
	Actions  []domain.Action
}

func Process(ctx Context, endpoint, contentType, encoding string, body []byte, scanner detector.ContentScanner, engine policy.Engine, vault *redactor.Vault) (Result, error) {
	return ProcessForProtocol(ctx, "", endpoint, contentType, encoding, body, scanner, engine, vault)
}

func ProcessForProtocol(ctx Context, expected domain.Protocol, endpoint, contentType, encoding string, body []byte, scanner detector.ContentScanner, engine policy.Engine, vault *redactor.Vault) (Result, error) {
	document, err := protocol.ParseExpected(expected, endpoint, contentType, encoding, body)
	if err != nil {
		return Result{}, err
	}
	replacements := make(map[string]string)
	result := Result{Vault: vault, Protocol: document.Protocol}
	for _, field := range document.Fields {
		processed, processErr := ProcessText(ctx, field.Path, field.Text, scanner, engine, vault)
		result.Findings = append(result.Findings, processed.Findings...)
		result.Actions = append(result.Actions, processed.Actions...)
		if processErr != nil {
			return result, processErr
		}
		if len(processed.Findings) > 0 {
			replacements[field.Path] = processed.Text
		}
	}
	result.Body, err = document.Replace(replacements)
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

// ProcessText applies the same detection, policy, approval, and vault semantics
// used for protocol body fields to one bounded metadata value.
func ProcessText(ctx Context, path, text string, scanner detector.ContentScanner, engine policy.Engine, vault *redactor.Vault) (TextResult, error) {
	result := TextResult{Text: text}
	matches, err := scanner.ScanChecked(path, text)
	if err != nil {
		return result, err
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Finding.Location.Start > matches[j].Finding.Location.Start })
	for _, match := range matches {
		decision, err := engine.Decide(policy.Scope{AgentID: ctx.AgentID, Workspace: ctx.Workspace, Provider: ctx.Provider, SurfaceID: ctx.SurfaceID, FindingType: match.Finding.Category}, ctx.Interactive)
		if err != nil {
			return result, err
		}
		result.Findings = append(result.Findings, match.Finding)
		result.Actions = append(result.Actions, decision.Action)
		action := decision.Action
		if action == domain.ActionAsk {
			if !ctx.Interactive || ctx.Approver == nil {
				return result, domain.NewError(domain.ErrInteractionRequired, "process request", "interactive policy decision is required")
			}
			requestContext := ctx.RequestContext
			if requestContext == nil {
				requestContext = context.Background()
			}
			action, err = ctx.Approver.Request(requestContext, match.Finding)
			if err != nil {
				return result, err
			}
			result.Actions[len(result.Actions)-1] = action
		}
		switch action {
		case domain.ActionBlock:
			return result, domain.NewError(domain.ErrPolicyBlocked, "process request", "policy blocked sensitive content")
		case domain.ActionRedact:
			placeholder, err := vault.Store(match.Finding.Category, match.Value)
			if err != nil {
				return result, err
			}
			start, end := match.Finding.Location.Start, match.Finding.Location.End
			result.Text = result.Text[:start] + placeholder + result.Text[end:]
		}
	}
	return result, nil
}
