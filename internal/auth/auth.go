package auth

import (
	"net/http"

	"github.com/agentveil/agentveil/internal/domain"
)

type Credentials interface {
	Resolve(source string) (string, error)
}
type Applier struct{ Credentials Credentials }

// Apply must be invoked only after the final request body has been installed.
func (a Applier) Apply(request *http.Request, strategy domain.AuthStrategy) error {
	switch strategy.Type {
	case domain.AuthPassthrough:
		return nil
	case domain.AuthBearer, domain.AuthAnthropicKey, domain.AuthGoogleKey:
		if a.Credentials == nil {
			return domain.NewError(domain.ErrInvalidContract, "apply auth", "credential resolver is unavailable")
		}
		value, err := a.Credentials.Resolve(strategy.Source)
		if err != nil {
			return domain.NewError(domain.ErrInvalidContract, "apply auth", "credential resolution failed")
		}
		switch strategy.Type {
		case domain.AuthBearer:
			request.Header.Set("Authorization", "Bearer "+value)
		case domain.AuthAnthropicKey:
			request.Header.Set("X-Api-Key", value)
		case domain.AuthGoogleKey:
			query := request.URL.Query()
			query.Set("key", value)
			request.URL.RawQuery = query.Encode()
		}
		return nil
	case domain.AuthAWSSigV4, domain.AuthVertexOAuth, domain.AuthCustom:
		return domain.NewError(domain.ErrInvalidContract, "apply auth", "signing strategy requires a registered provider-specific signer")
	default:
		return domain.NewError(domain.ErrInvalidContract, "apply auth", "unknown authentication strategy")
	}
}
