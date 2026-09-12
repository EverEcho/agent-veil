package auth

import (
	"net/http"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

const MaxCredentialBytes = 4096

type Credentials interface {
	Resolve(source string) (string, error)
}
type Signer interface{ Apply(*http.Request) error }
type Applier struct {
	Credentials Credentials
	Signers     map[domain.AuthType]Signer
}

// Apply must be invoked only after the final request body has been installed.
func (a Applier) Apply(request *http.Request, strategy domain.AuthStrategy) error {
	if request == nil || request.URL == nil {
		return domain.NewError(domain.ErrInvalidContract, "apply auth", "request and URL are required")
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	if strategy.Type != domain.AuthPassthrough {
		clearProviderCredentials(request)
	}
	switch strategy.Type {
	case domain.AuthPassthrough:
		return nil
	case domain.AuthBearer, domain.AuthAnthropicKey, domain.AuthGoogleKey, domain.AuthVertexOAuth:
		if a.Credentials == nil {
			return domain.NewError(domain.ErrInvalidContract, "apply auth", "credential resolver is unavailable")
		}
		value, err := a.Credentials.Resolve(strategy.Source)
		if err != nil || !validCredentialValue(value) {
			return domain.NewError(domain.ErrInvalidContract, "apply auth", "credential resolution failed")
		}
		switch strategy.Type {
		case domain.AuthBearer, domain.AuthVertexOAuth:
			request.Header.Set("Authorization", "Bearer "+value)
		case domain.AuthAnthropicKey:
			request.Header.Set("X-Api-Key", value)
		case domain.AuthGoogleKey:
			query := request.URL.Query()
			query.Set("key", value)
			request.URL.RawQuery = query.Encode()
		}
		return nil
	case domain.AuthAWSSigV4, domain.AuthCustom:
		signer := a.Signers[strategy.Type]
		if signer == nil {
			return domain.NewError(domain.ErrInvalidContract, "apply auth", "signing strategy requires a registered provider-specific signer")
		}
		return signer.Apply(request)
	default:
		return domain.NewError(domain.ErrInvalidContract, "apply auth", "unknown authentication strategy")
	}
}

func validCredentialValue(value string) bool {
	if len(value) == 0 || len(value) > MaxCredentialBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func clearProviderCredentials(request *http.Request) {
	for _, header := range []string{"Authorization", "X-Api-Key", "X-Goog-Api-Key", "X-Amz-Security-Token", "X-Amz-Date", "X-Amz-Content-Sha256"} {
		request.Header.Del(header)
	}
	query := request.URL.Query()
	for key := range query {
		if strings.EqualFold(key, "key") {
			query.Del(key)
		}
	}
	request.URL.RawQuery = query.Encode()
}
