package detector

import (
	"errors"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/agentveil/agentveil/internal/domain"
)

type SemanticToken struct {
	Text       string
	Start, End int
}

type SemanticModel interface {
	Predict([]SemanticToken) ([]map[string]float64, error)
}

type SemanticResourceUsage struct {
	ResidentBytes  uint64 `json:"resident_bytes"`
	WorkerCount    uint32 `json:"worker_count"`
	Accelerator    string `json:"accelerator"`
	InferenceCount uint64 `json:"inference_count"`
}

func (u SemanticResourceUsage) Validate() error {
	if u.ResidentBytes > 1<<50 || u.WorkerCount > 4096 || !validEntityName(u.Accelerator) {
		return domain.NewError(domain.ErrInvalidContract, "validate semantic resource usage", "resource metrics are invalid")
	}
	return nil
}

type SemanticResourceReporter interface {
	SemanticResourceUsage() (SemanticResourceUsage, error)
}

type SemanticEntity struct {
	Category string
	Severity domain.Severity
	Action   domain.Action
}

type LocalSemantic struct {
	model     SemanticModel
	entities  map[string]SemanticEntity
	maxTokens int
}

func NewLocalSemantic(model SemanticModel, entities map[string]SemanticEntity, maxTokens int) (*LocalSemantic, error) {
	if model == nil || len(entities) == 0 || maxTokens < 1 {
		return nil, domain.NewError(domain.ErrInvalidContract, "create semantic detector", "model, entities, and token limit are required")
	}
	copyEntities := make(map[string]SemanticEntity, len(entities))
	for name, entity := range entities {
		if !validEntityName(name) || !strings.HasPrefix(entity.Category, "pii.") || !entity.Severity.Valid() || !entity.Action.Valid() {
			return nil, domain.NewError(domain.ErrInvalidContract, "create semantic detector", "entity mapping is invalid")
		}
		copyEntities[name] = entity
	}
	return &LocalSemantic{model: model, entities: copyEntities, maxTokens: maxTokens}, nil
}

func TokenizeSemantic(text string) ([]SemanticToken, error) {
	if !utf8.ValidString(text) {
		return nil, domain.NewError(domain.ErrDetectorFailure, "tokenize semantic content", "content is not valid UTF-8")
	}
	tokens := make([]SemanticToken, 0, utf8.RuneCountInString(text))
	for start, character := range text {
		end := start + utf8.RuneLen(character)
		tokens = append(tokens, SemanticToken{Text: text[start:end], Start: start, End: end})
	}
	return tokens, nil
}

func (s *LocalSemantic) Detect(path, text string) ([]domain.Finding, error) {
	tokens, err := TokenizeSemantic(text)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, nil
	}
	overlap := s.maxTokens / 4
	if overlap == 0 && s.maxTokens > 1 {
		overlap = 1
	}
	var matches []Match
	for start := 0; start < len(tokens); {
		end := start + s.maxTokens
		if end > len(tokens) {
			end = len(tokens)
		}
		window := tokens[start:end]
		scores, err := s.model.Predict(window)
		if err != nil {
			return nil, err
		}
		if len(scores) != len(window) {
			return nil, domain.NewError(domain.ErrDetectorFailure, "semantic detection", "model score count does not match tokens")
		}
		labels, confidences, err := decodeBIES(scores, s.entities)
		if err != nil {
			return nil, domain.NewError(domain.ErrDetectorFailure, "semantic detection", "model returned invalid BIES scores")
		}
		for _, finding := range semanticFindings(path, window, labels, confidences, s.entities) {
			matches = append(matches, Match{Finding: finding, Value: text[finding.Location.Start:finding.Location.End]})
		}
		if end == len(tokens) {
			break
		}
		start = end - overlap
	}
	merged := Merge(matches)
	findings := make([]domain.Finding, len(merged))
	for index := range merged {
		findings[index] = merged[index].Finding
	}
	return findings, nil
}

type biesLabel struct {
	prefix, entity string
}

func decodeBIES(scores []map[string]float64, entities map[string]SemanticEntity) ([]biesLabel, []float64, error) {
	if len(scores) == 0 {
		return nil, nil, nil
	}
	labels := []biesLabel{{prefix: "O"}}
	for entity := range entities {
		for _, prefix := range []string{"B", "I", "E", "S"} {
			labels = append(labels, biesLabel{prefix: prefix, entity: entity})
		}
	}
	sort.Slice(labels[1:], func(i, j int) bool {
		left, right := labels[i+1], labels[j+1]
		return left.entity+left.prefix < right.entity+right.prefix
	})
	const impossible = -math.MaxFloat64
	paths := make([][]int, len(scores))
	previous := make([]float64, len(labels))
	for index := range previous {
		previous[index] = impossible
	}
	for labelIndex, label := range labels {
		if validStart(label) {
			previous[labelIndex] = labelScore(scores[0], label)
		}
	}
	for position := 1; position < len(scores); position++ {
		paths[position] = make([]int, len(labels))
		current := make([]float64, len(labels))
		for nextIndex, next := range labels {
			current[nextIndex] = impossible
			emission := labelScore(scores[position], next)
			if emission == impossible {
				continue
			}
			for priorIndex, prior := range labels {
				if previous[priorIndex] == impossible || !validTransition(prior, next) {
					continue
				}
				candidate := previous[priorIndex] + emission
				if candidate > current[nextIndex] {
					current[nextIndex], paths[position][nextIndex] = candidate, priorIndex
				}
			}
		}
		previous = current
	}
	best, bestScore := -1, impossible
	for index, label := range labels {
		if validEnd(label) && previous[index] > bestScore {
			best, bestScore = index, previous[index]
		}
	}
	if best < 0 || bestScore == impossible {
		return nil, nil, errors.New("no valid BIES path")
	}
	result := make([]biesLabel, len(scores))
	confidence := make([]float64, len(scores))
	for position := len(scores) - 1; position >= 0; position-- {
		result[position] = labels[best]
		confidence[position] = normalizedConfidence(scores[position], result[position])
		if position > 0 {
			best = paths[position][best]
		}
	}
	return result, confidence, nil
}

func labelScore(scores map[string]float64, label biesLabel) float64 {
	value, ok := scores[labelName(label)]
	if !ok || math.IsNaN(value) || math.IsInf(value, 0) {
		return -math.MaxFloat64
	}
	return value
}

func labelName(label biesLabel) string {
	if label.prefix == "O" {
		return "O"
	}
	return label.prefix + "-" + label.entity
}

func validStart(label biesLabel) bool {
	return label.prefix == "O" || label.prefix == "B" || label.prefix == "S"
}
func validEnd(label biesLabel) bool {
	return label.prefix == "O" || label.prefix == "E" || label.prefix == "S"
}
func validTransition(prior, next biesLabel) bool {
	if prior.prefix == "B" || prior.prefix == "I" {
		return prior.entity == next.entity && (next.prefix == "I" || next.prefix == "E")
	}
	return next.prefix == "O" || next.prefix == "B" || next.prefix == "S"
}

func normalizedConfidence(scores map[string]float64, chosen biesLabel) float64 {
	chosenScore, ok := scores[labelName(chosen)]
	if !ok {
		return 0
	}
	maximum := chosenScore
	for _, score := range scores {
		if score > maximum && !math.IsNaN(score) {
			maximum = score
		}
	}
	sum := 0.0
	for _, score := range scores {
		if !math.IsNaN(score) && !math.IsInf(score, 0) {
			sum += math.Exp(score - maximum)
		}
	}
	if sum == 0 {
		return 0
	}
	return math.Exp(chosenScore-maximum) / sum
}

func semanticFindings(path string, tokens []SemanticToken, labels []biesLabel, confidences []float64, entities map[string]SemanticEntity) []domain.Finding {
	var findings []domain.Finding
	for index := 0; index < len(labels); index++ {
		label := labels[index]
		if label.prefix == "O" {
			continue
		}
		start, end, confidence := index, index, confidences[index]
		if label.prefix == "B" {
			for labels[end].prefix != "E" {
				end++
				confidence += confidences[end]
			}
		}
		entity := entities[label.entity]
		findings = append(findings, domain.Finding{RuleID: "semantic." + label.entity, Category: entity.Category, Severity: entity.Severity, Location: domain.ContentLocation{Path: path, Start: tokens[start].Start, End: tokens[end].End}, Confidence: confidence / float64(end-start+1), Detector: "semantic", SuggestedAction: entity.Action})
		index = end
	}
	return findings
}

func validEntityName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '_' {
					return false
				}
			}
		}
	}
	return true
}
