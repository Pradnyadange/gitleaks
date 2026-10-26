package audit

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
	Entropy       float32  `json:"entropy"`
	Tags          []string `json:"tags,omitempty"`
	MaskedSecret  string   `json:"masked_secret"`
	CodeContext   []string `json:"code_context"`
	PathType      string   `json:"path_type"`
	InHistoryOnly bool     `json:"in_history_only"`
}