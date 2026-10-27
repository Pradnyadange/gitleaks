package audit

type Triage struct {
	Verdict    string  `json:"verdict"`    // real_secret | likely_false_positive | needs_review
	Confidence float64 `json:"confidence"` // 0.0-1.0
	Reason     string  `json:"reason"`     // one sentence, max 160 chars
	Source     string  `json:"source"`     // llm | heuristic
	Cached     bool    `json:"cached"`
}

type EnrichedFinding struct {
	Fingerprint   string   `json:"fingerprint"`
	RuleID        string   `json:"rule_id"`
	Description   string   `json:"description"`
	File          string   `json:"file"`
	StartLine     int      `json:"start_line"`
	EndLine       int      `json:"end_line"`
	Commit        string   `json:"commit,omitempty"`
	Author        string   `json:"author,omitempty"`
	Date          string   `json:"date,omitempty"`
	Entropy       float64  `json:"entropy"`
	Tags          []string `json:"tags,omitempty"`
	MaskedSecret  string   `json:"masked_secret"`
	SecretLength  int      `json:"secret_length"`
	CodeContext   []string `json:"code_context"`
	PathType      string   `json:"path_type"`
	InHistoryOnly bool     `json:"in_history_only"`
	Triage        *Triage  `json:"triage,omitempty"`
}
