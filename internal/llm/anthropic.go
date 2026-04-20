package llm

import (
	"context"
	"fmt"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

type AnthropicClient struct {
	client anthropic.Client
	model  string
}

var _ ChatClient = (*AnthropicClient)(nil)

func NewAnthropicClient(apiKey, model string, maxRetries int) *AnthropicClient {
	return &AnthropicClient{
		client: anthropic.NewClient(
			option.WithAPIKey(apiKey),
			option.WithMaxRetries(maxRetries),
		),
		model: model,
	}
}

func (c *AnthropicClient) Chat(ctx context.Context, systemPrompt string, messages []ChatMessage) (string, error) {
	var msgParams []anthropic.MessageParam

	systemBlock := []anthropic.TextBlockParam{
		{Text: systemPrompt},
	}

	for _, m := range messages {
		role := anthropic.MessageParamRoleUser
		if m.Role == "assistant" {
			role = anthropic.MessageParamRoleAssistant
		}
		msgParams = append(msgParams, anthropic.MessageParam{
			Role: role,
			Content: []anthropic.ContentBlockParamUnion{
				anthropic.NewTextBlock(m.Content),
			},
		})
	}

	resp, err := c.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(c.model),
		MaxTokens: MAX_TOKENS_ANTHROPIC,
		System:    systemBlock,
		Messages:  msgParams,
	})
	if err != nil {
		return "", err
	}

	for _, block := range resp.Content {
		if textBlock, ok := block.AsAny().(anthropic.TextBlock); ok {
			return textBlock.Text, nil
		}
	}
	return "", fmt.Errorf("LLM response contained no text blocks")
}
