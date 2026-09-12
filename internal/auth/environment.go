package auth

import (
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/agentveil/agentveil/internal/domain"
)

var environmentName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

type EnvironmentCredentials struct{}

func (EnvironmentCredentials) Resolve(source string) (string, error) {
	name, ok := strings.CutPrefix(source, "environment:")
	if !ok || !environmentName.MatchString(name) {
		return "", domain.NewError(domain.ErrInvalidContract, "resolve credential", "source must name an environment variable")
	}
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return "", domain.NewError(domain.ErrInvalidContract, "resolve credential", "environment credential is unavailable")
	}
	return value, nil
}

func (EnvironmentCredentials) ResolveAWS(source string) (AWSCredentials, error) {
	if source != "" && source != "environment:aws-default" {
		return AWSCredentials{}, domain.NewError(domain.ErrInvalidContract, "resolve AWS credential", "unsupported AWS credential source")
	}
	accessKey, accessOK := os.LookupEnv("AWS_ACCESS_KEY_ID")
	secretKey, secretOK := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	if !accessOK || !secretOK || accessKey == "" || secretKey == "" {
		return AWSCredentials{}, domain.NewError(domain.ErrInvalidContract, "resolve AWS credential", "AWS environment credentials are unavailable")
	}
	return AWSCredentials{AccessKey: accessKey, SecretKey: secretKey, SessionToken: os.Getenv("AWS_SESSION_TOKEN")}, nil
}

func NewRuntimeApplier(strategy domain.AuthStrategy, upstream *url.URL) (Applier, error) {
	credentials := EnvironmentCredentials{}
	applier := Applier{Credentials: credentials}
	switch strategy.Type {
	case "", domain.AuthPassthrough, domain.AuthBearer, domain.AuthAnthropicKey, domain.AuthGoogleKey, domain.AuthVertexOAuth:
		return applier, nil
	case domain.AuthAWSSigV4:
		region, service, ok := awsScope(upstream)
		if !ok {
			return Applier{}, domain.NewError(domain.ErrInvalidContract, "configure auth", "AWS SigV4 requires a recognized Bedrock endpoint")
		}
		applier.Signers = map[domain.AuthType]Signer{domain.AuthAWSSigV4: AWSSigner{Region: region, Service: service, Source: strategy.Source, Credentials: credentials}}
		return applier, nil
	case domain.AuthCustom:
		return Applier{}, domain.NewError(domain.ErrInvalidContract, "configure auth", "custom authentication requires an explicitly registered signer")
	default:
		return Applier{}, domain.NewError(domain.ErrInvalidContract, "configure auth", "unknown authentication strategy")
	}
}

func awsScope(upstream *url.URL) (string, string, bool) {
	if upstream == nil || !strings.EqualFold(upstream.Scheme, "https") {
		return "", "", false
	}
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(upstream.Hostname(), ".")), ".")
	if len(labels) < 4 || (labels[0] != "bedrock" && labels[0] != "bedrock-runtime") || labels[2] != "amazonaws" || labels[3] != "com" {
		return "", "", false
	}
	if len(labels) != 4 && !(len(labels) == 5 && labels[4] == "cn") {
		return "", "", false
	}
	if labels[1] == "" {
		return "", "", false
	}
	return labels[1], "bedrock", true
}
