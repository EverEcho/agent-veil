package redactor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"

	"github.com/agentveil/agentveil/internal/domain"
)

var (
	typeCleaner       = regexp.MustCompile(`[^A-Z0-9]+`)
	completeToken     = regexp.MustCompile(`\[\[VEIL_[A-Z0-9_]+_[A-F0-9]{16,64}\]\]`)
	possibleTokenOpen = regexp.MustCompile(`\[\[VEIL_`)
)

type Limits struct {
	MaxEntries       int
	MaxOriginalBytes int
}

const (
	MinSessionSecretBytes = 32
	MaxSessionSecretBytes = 64
	MaxVaultEntries       = 64 << 10
	MaxVaultOriginalBytes = 64 << 20
)

type Vault struct {
	mu            sync.RWMutex
	sessionSecret []byte
	limits        Limits
	entries       map[string][]byte
	originalBytes int
	destroyed     bool
}

func NewVault(sessionSecret []byte, limits Limits) (*Vault, error) {
	if len(sessionSecret) < MinSessionSecretBytes || len(sessionSecret) > MaxSessionSecretBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "create vault", "session secret length must be within its configured bounds")
	}
	if limits.MaxEntries <= 0 || limits.MaxEntries > MaxVaultEntries || limits.MaxOriginalBytes <= 0 || limits.MaxOriginalBytes > MaxVaultOriginalBytes {
		return nil, domain.NewError(domain.ErrInvalidContract, "create vault", "vault limits must be within configured bounds")
	}
	return &Vault{sessionSecret: append([]byte(nil), sessionSecret...), limits: limits, entries: make(map[string][]byte)}, nil
}

func (v *Vault) Store(findingType, original string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.destroyed {
		return "", domain.NewError(domain.ErrVaultDestroyed, "store placeholder", "request vault has been destroyed")
	}
	cleanType := strings.Trim(typeCleaner.ReplaceAllString(strings.ToUpper(findingType), "_"), "_")
	if cleanType == "" || original == "" {
		return "", domain.NewError(domain.ErrInvalidContract, "store placeholder", "finding type and original value are required")
	}
	mac := hmac.New(sha256.New, v.sessionSecret)
	_, _ = mac.Write([]byte(cleanType))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(original))
	id := strings.ToUpper(hex.EncodeToString(mac.Sum(nil)[:8]))
	placeholder := "[[VEIL_" + cleanType + "_" + id + "]]"
	if stored, ok := v.entries[placeholder]; ok {
		if string(stored) != original {
			return "", domain.NewError(domain.ErrInvalidContract, "store placeholder", "placeholder collision")
		}
		return placeholder, nil
	}
	if len(v.entries) >= v.limits.MaxEntries || v.originalBytes+len(original) > v.limits.MaxOriginalBytes {
		return "", domain.NewError(domain.ErrVaultFull, "store placeholder", "request vault capacity exhausted")
	}
	v.entries[placeholder] = []byte(original)
	v.originalBytes += len(original)
	return placeholder, nil
}

func (v *Vault) Restore(input string) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.destroyed {
		return "", domain.NewError(domain.ErrVaultDestroyed, "restore placeholder", "request vault has been destroyed")
	}
	indices := completeToken.FindAllStringIndex(input, -1)
	var result strings.Builder
	last := 0
	for _, index := range indices {
		placeholder := input[index[0]:index[1]]
		original, ok := v.entries[placeholder]
		if !ok {
			return "", domain.NewError(domain.ErrUnknownPlaceholder, "restore placeholder", "placeholder is not present in this request vault")
		}
		result.WriteString(input[last:index[0]])
		result.Write(original)
		last = index[1]
	}
	result.WriteString(input[last:])
	if possibleTokenOpen.MatchString(completeToken.ReplaceAllString(input, "")) {
		return "", domain.NewError(domain.ErrMalformedPlaceholder, "restore placeholder", "malformed or incomplete placeholder")
	}
	return result.String(), nil
}

// RestoreParts restores placeholders that may cross logical protocol fields
// while preserving the field sequence. Unknown or malformed tokens fail closed.
func (v *Vault) RestoreParts(parts []string) ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.destroyed {
		return nil, domain.NewError(domain.ErrVaultDestroyed, "restore placeholder", "request vault has been destroyed")
	}
	combined := strings.Join(parts, "")
	indices := completeToken.FindAllStringIndex(combined, -1)
	if possibleTokenOpen.MatchString(completeToken.ReplaceAllString(combined, "")) {
		return nil, domain.NewError(domain.ErrMalformedPlaceholder, "restore placeholder", "malformed or incomplete placeholder")
	}
	boundaries := make([]int, len(parts)+1)
	for i, part := range parts {
		boundaries[i+1] = boundaries[i] + len(part)
	}
	result := append([]string(nil), parts...)
	for i := len(indices) - 1; i >= 0; i-- {
		index := indices[i]
		token := combined[index[0]:index[1]]
		original, ok := v.entries[token]
		if !ok {
			return nil, domain.NewError(domain.ErrUnknownPlaceholder, "restore placeholder", "placeholder is not present in this request vault")
		}
		startSegment, endSegment := segmentAt(boundaries, index[0]), segmentAt(boundaries, index[1]-1)
		startLocal := index[0] - boundaries[startSegment]
		endLocal := index[1] - boundaries[endSegment]
		if startSegment == endSegment {
			result[startSegment] = result[startSegment][:startLocal] + string(original) + result[startSegment][endLocal:]
			continue
		}
		result[startSegment] = result[startSegment][:startLocal] + string(original)
		for segment := startSegment + 1; segment < endSegment; segment++ {
			result[segment] = ""
		}
		result[endSegment] = result[endSegment][endLocal:]
	}
	return result, nil
}

func segmentAt(boundaries []int, offset int) int {
	for i := 1; i < len(boundaries); i++ {
		if offset < boundaries[i] {
			return i - 1
		}
	}
	return len(boundaries) - 2
}

func (v *Vault) Destroy() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for key, original := range v.entries {
		for i := range original {
			original[i] = 0
		}
		delete(v.entries, key)
	}
	for i := range v.sessionSecret {
		v.sessionSecret[i] = 0
	}
	v.originalBytes = 0
	v.destroyed = true
}

func (v *Vault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.entries)
}
