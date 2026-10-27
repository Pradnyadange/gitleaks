package audit

import "context"

type LLMClient interface {
	Classify(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}
