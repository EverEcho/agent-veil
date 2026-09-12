package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

type AWSCredentials struct{ AccessKey, SecretKey, SessionToken string }
type AWSCredentialProvider interface {
	ResolveAWS(source string) (AWSCredentials, error)
}
type AWSSigner struct {
	Region, Service, Source string
	Credentials             AWSCredentialProvider
	Now                     func() time.Time
	MaxBodyBytes            int64
}

const MaxSigningBodyBytes int64 = 64 << 20

func (s AWSSigner) Apply(request *http.Request) error {
	if request == nil || request.URL == nil || request.URL.Host == "" || s.Credentials == nil || s.Region == "" || s.Service == "" {
		return domain.NewError(domain.ErrInvalidContract, "sign SigV4", "signer is incomplete")
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	limit := s.MaxBodyBytes
	if limit == 0 {
		limit = MaxSigningBodyBytes
	}
	if limit < 1 || limit > MaxSigningBodyBytes || request.ContentLength > limit {
		return domain.NewError(domain.ErrInvalidContract, "sign SigV4", "request body exceeds its signing limit")
	}
	credentials, err := s.Credentials.ResolveAWS(s.Source)
	if err != nil || !validCredentialValue(credentials.AccessKey) || !validCredentialValue(credentials.SecretKey) || credentials.SessionToken != "" && !validCredentialValue(credentials.SessionToken) {
		return domain.NewError(domain.ErrInvalidContract, "sign SigV4", "credentials are unavailable")
	}
	body := []byte(nil)
	if request.Body != nil {
		body, err = io.ReadAll(io.LimitReader(request.Body, limit+1))
	}
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return domain.NewError(domain.ErrInvalidContract, "sign SigV4", "request body exceeds its signing limit")
	}
	request.Body = io.NopCloser(strings.NewReader(string(body)))
	request.ContentLength = int64(len(body))
	payloadHash := sha256.Sum256(body)
	payloadHex := hex.EncodeToString(payloadHash[:])
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	amzDate, date := now.Format("20060102T150405Z"), now.Format("20060102")
	request.Header.Set("X-Amz-Date", amzDate)
	request.Header.Set("X-Amz-Content-Sha256", payloadHex)
	if credentials.SessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", credentials.SessionToken)
	}
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := "host:" + request.URL.Host + "\n" + "x-amz-content-sha256:" + payloadHex + "\n" + "x-amz-date:" + amzDate + "\n"
	if credentials.SessionToken != "" {
		signedHeaders += ";x-amz-security-token"
		canonicalHeaders += "x-amz-security-token:" + collapse(credentials.SessionToken) + "\n"
	}
	canonicalURI := request.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := strings.ReplaceAll(request.URL.Query().Encode(), "+", "%20")
	canonicalRequest := request.Method + "\n" + canonicalURI + "\n" + canonicalQuery + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHex
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + s.Region + "/" + s.Service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(requestHash[:])
	dateKey := hmacBytes([]byte("AWS4"+credentials.SecretKey), date)
	regionKey := hmacBytes(dateKey, s.Region)
	serviceKey := hmacBytes(regionKey, s.Service)
	signingKey := hmacBytes(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacBytes(signingKey, stringToSign))
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+credentials.AccessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
	return nil
}

func hmacBytes(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
func collapse(value string) string { return strings.Join(strings.Fields(value), " ") }
