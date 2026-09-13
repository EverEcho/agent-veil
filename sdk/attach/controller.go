// Package attach provides the fail-closed lifecycle used by Agent-specific
// adapters that can change a running process's routing without restarting it.
package attach

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
	native "github.com/agentveil/agentveil/sdk/native"
)

const cleanupTimeout = 2 * time.Second

type Options struct {
	LeaseTTL          time.Duration
	HeartbeatInterval time.Duration
	SessionTTL        time.Duration
	Interactive       bool
}

// RouteBinding contains only the short-lived authority needed by one attached
// Surface. Target implementations must never receive the management token.
type RouteBinding struct {
	SurfaceID       string            `json:"surface_id"`
	RouteID         string            `json:"route_id"`
	Protocol        native.Protocol   `json:"protocol"`
	RouteURL        string            `json:"route_url"`
	BaseURL         string            `json:"base_url"`
	Headers         map[string]string `json:"headers"`
	CapabilityValue string            `json:"capability_value"`
}

type Binding struct {
	SessionID string         `json:"session_id"`
	ExpiresAt time.Time      `json:"expires_at"`
	Routes    []RouteBinding `json:"routes"`
}

// Target applies an Agent-specific dynamic configuration. Apply must replace
// the previous Binding atomically. Restore must be idempotent and restore the
// exact pre-Attach state, including after a partially failed Apply.
type Target interface {
	Apply(context.Context, Binding) error
	Restore(context.Context) error
}

type Controller struct {
	client *native.Client
}

func New(endpoint, managementToken string, transport *http.Client) (*Controller, error) {
	client, err := native.NewClient(endpoint, managementToken, transport)
	if err != nil {
		return nil, err
	}
	return &Controller{client: client}, nil
}

// Run owns one Attach lease until cancellation or failure. Route credentials
// are rotated before expiry; a failed heartbeat or reconfiguration restores
// the target and revokes all issued authority before returning.
func (c *Controller) Run(ctx context.Context, manifest native.AgentManifest, target Target, options Options) (resultErr error) {
	if c == nil || c.client == nil || ctx == nil || target == nil || manifest.Agent.Mode != native.ModeAttach || options.LeaseTTL < 2*time.Second || options.LeaseTTL > time.Hour || options.HeartbeatInterval < 100*time.Millisecond || options.HeartbeatInterval >= options.LeaseTTL || options.SessionTTL < 2*time.Second || options.SessionTTL > 24*time.Hour || options.LeaseTTL%time.Second != 0 || options.SessionTTL%time.Second != 0 {
		return domain.NewError(domain.ErrInvalidContract, "attach integration", "Attach manifest, target, and bounded lifecycle timings are required")
	}
	registration, err := c.client.Register(ctx, manifest, options.LeaseTTL)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if cleanupErr := c.client.Remove(cleanupCtx, manifest.Agent.ID, registration.Generation); cleanupErr != nil && resultErr == nil {
			resultErr = fmt.Errorf("remove Attach lease: %w", cleanupErr)
		}
	}()

	routeIDs, err := protectedRouteIDs(registration)
	if err != nil {
		return err
	}
	current, err := c.client.CreateSession(ctx, routeIDs, options.SessionTTL, options.Interactive)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if cleanupErr := c.client.DeleteSession(cleanupCtx, current.Session.ID); cleanupErr != nil && resultErr == nil {
			resultErr = fmt.Errorf("revoke Attach session: %w", cleanupErr)
		}
	}()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if restoreErr := target.Restore(cleanupCtx); restoreErr != nil && resultErr == nil {
			resultErr = fmt.Errorf("restore attached target: %w", restoreErr)
		}
	}()
	if err := target.Apply(ctx, makeBinding(registration, current)); err != nil {
		return fmt.Errorf("apply Attach routing: %w", err)
	}

	heartbeat := time.NewTicker(options.HeartbeatInterval)
	defer heartbeat.Stop()
	rotateAfter := options.SessionTTL / 2
	rotation := time.NewTimer(rotateAfter)
	defer rotation.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			if _, err := c.client.Heartbeat(ctx, manifest.Agent.ID, registration.Generation, options.LeaseTTL); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("maintain Attach lease: %w", err)
			}
		case <-rotation.C:
			next, err := c.client.CreateSession(ctx, routeIDs, options.SessionTTL, options.Interactive)
			if err != nil {
				return fmt.Errorf("rotate Attach session: %w", err)
			}
			if err := target.Apply(ctx, makeBinding(registration, next)); err != nil {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
				_ = c.client.DeleteSession(cleanupCtx, next.Session.ID)
				cancel()
				return fmt.Errorf("apply rotated Attach routing: %w", err)
			}
			cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
			deleteErr := c.client.DeleteSession(cleanupCtx, current.Session.ID)
			cancel()
			if deleteErr != nil {
				// The target already uses next. Keep it as the deferred cleanup
				// target; removing the registration below also revokes both Route
				// generations if the old Session cannot be deleted directly.
				current = next
				return fmt.Errorf("revoke previous Attach session: %w", deleteErr)
			}
			current = next
			rotation.Reset(rotateAfter)
		}
	}
}

func protectedRouteIDs(registration native.Registration) ([]string, error) {
	summary := registration.Plan.Summary
	if registration.State != "active" || len(registration.Plan.Routes) == 0 || summary.Total == 0 || summary.Protected != len(registration.Plan.Routes) || summary.Protected+summary.Local != summary.Total || summary.Partial != 0 || summary.Observed != 0 || summary.Unprotected != 0 {
		return nil, errors.New("Attach manifest does not have a fully protected route set")
	}
	result := make([]string, len(registration.Plan.Routes))
	for index, route := range registration.Plan.Routes {
		result[index] = route.ID
	}
	return result, nil
}

func makeBinding(registration native.Registration, created native.CreatedSession) Binding {
	credentials := make(map[string]string, len(created.Routes))
	for _, credential := range created.Routes {
		credentials[credential.RouteID] = credential.Token
	}
	binding := Binding{SessionID: created.Session.ID, ExpiresAt: created.Session.ExpiresAt, Routes: make([]RouteBinding, 0, len(registration.Plan.Routes))}
	for _, route := range registration.Plan.Routes {
		token := credentials[route.ID]
		routeURL := created.Session.CoreEndpoint + "/route/" + route.ID
		binding.Routes = append(binding.Routes, RouteBinding{
			SurfaceID:       route.SurfaceID,
			RouteID:         route.ID,
			Protocol:        route.Protocol,
			RouteURL:        routeURL,
			BaseURL:         clientBaseURL(routeURL, route.Protocol),
			Headers:         map[string]string{"X-Veil-Session": created.Session.ID, "X-Veil-Route-Token": token},
			CapabilityValue: "veil-v1:" + created.Session.ID + ":" + token,
		})
	}
	return binding
}

func clientBaseURL(routeURL string, protocol native.Protocol) string {
	switch protocol {
	case native.ProtocolOpenAIChat, native.ProtocolOpenAIResponses:
		return routeURL + "/v1"
	case native.ProtocolMCPHTTP, native.ProtocolMCPStreamable, native.ProtocolMCPLegacySSE:
		return routeURL + "/mcp"
	default:
		return routeURL
	}
}
