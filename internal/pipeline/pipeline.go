package pipeline

import (
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
}
type Result struct {
	Body     []byte
	Findings []domain.Finding
	Actions  []domain.Action
	Vault    *redactor.Vault
}

func Process(ctx Context, endpoint, contentType, encoding string, body []byte, scanner *detector.Scanner, engine policy.Engine, vault *redactor.Vault) (Result, error) {
	document, err := protocol.Parse(endpoint, contentType, encoding, body)
	if err != nil {
		return Result{}, err
	}
	replacements := make(map[string]string)
	result := Result{Vault: vault}
	for _, field := range document.Fields {
		matches, scanErr := scanner.ScanChecked(field.Path, field.Text)
		if scanErr != nil {
			return Result{}, scanErr
		}
		sort.Slice(matches, func(i, j int) bool { return matches[i].Finding.Location.Start > matches[j].Finding.Location.Start })
		text := field.Text
		for _, match := range matches {
			decision, err := engine.Decide(policy.Scope{AgentID: ctx.AgentID, Workspace: ctx.Workspace, Provider: ctx.Provider, SurfaceID: ctx.SurfaceID, FindingType: match.Finding.Category}, ctx.Interactive)
			if err != nil {
				return Result{}, err
			}
			result.Findings = append(result.Findings, match.Finding)
			result.Actions = append(result.Actions, decision.Action)
			switch decision.Action {
			case domain.ActionBlock:
				return Result{}, domain.NewError(domain.ErrPolicyBlocked, "process request", "policy blocked sensitive content")
			case domain.ActionRedact:
				placeholder, err := vault.Store(match.Finding.Category, match.Value)
				if err != nil {
					return Result{}, err
				}
				start, end := match.Finding.Location.Start, match.Finding.Location.End
				text = text[:start] + placeholder + text[end:]
			case domain.ActionAsk:
				return Result{}, domain.NewError(domain.ErrInteractionRequired, "process request", "interactive policy decision is required")
			}
		}
		if len(matches) > 0 {
			replacements[field.Path] = text
		}
	}
	result.Body, err = document.Replace(replacements)
	if err != nil {
		return Result{}, err
	}
	return result, nil
}
