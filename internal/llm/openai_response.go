package llm

import (
	"context"
	"fmt"
	"strings"

	openai "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
)

// OpenAIResponseClient implements ChatClient using the OpenAI Responses API
// instead of the Chat Completions API.
type OpenAIResponseClient struct {
	client openai.Client
	model  string
}

var _ ChatClient = (*OpenAIResponseClient)(nil)

func NewOpenAIResponseClient(apiKey, model string, maxRetries int) *OpenAIResponseClient {
	return &OpenAIResponseClient{
		client: openai.NewClient(
			option.WithAPIKey(apiKey),
			option.WithMaxRetries(maxRetries),
		),
		model: model,
	}
}

// Chat implements ChatClient using the Responses API.
// The system prompt and all user/assistant messages are concatenated into
// a single input string since the Responses API uses a single Input field.
func (c *OpenAIResponseClient) Chat(ctx context.Context, systemPrompt string, messages []ChatMessage) (string, error) {
	// Build input: prepend system prompt as an instruction block, then
	// append each message turn in order.
	var sb strings.Builder

	if systemPrompt != "" {
		sb.WriteString("[SYSTEM]: ")
		sb.WriteString(systemPrompt)
		sb.WriteString("\n\n")
	}

	for _, m := range messages {
		switch m.Role {
		case "assistant":
			sb.WriteString("[ASSISTANT]: ")
		default: // user
			sb.WriteString("[USER]: ")
		}
		sb.WriteString(m.Content)
		sb.WriteString("\n")
	}

	input := strings.TrimSpace(sb.String())

	resp, err := c.client.Responses.New(ctx, responses.ResponseNewParams{
		Input: responses.ResponseNewParamsInputUnion{
			OfString: openai.String(input),
		},
		Model: openai.ChatModel(c.model),
	})
	if err != nil {
		return "", fmt.Errorf("openai responses API error: %w", err)
	}

	text := resp.OutputText()
	if text == "" {
		return "", fmt.Errorf("openai responses API returned empty output")
	}

	return text, nil
}
