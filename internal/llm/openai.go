package llm

import (
	"context"
	"fmt"

	openai "github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/shared"
)

type OpenAIClient struct {
	client openai.Client
	model  string
}

var _ ChatClient = (*OpenAIClient)(nil)

func NewOpenAIClient(apiKey, model string, maxRetries int) *OpenAIClient {
	return &OpenAIClient{
		client: openai.NewClient(
			option.WithAPIKey(apiKey),
			option.WithMaxRetries(maxRetries),
		),
		model: model,
	}
}

func (c *OpenAIClient) Chat(ctx context.Context, systemPrompt string, messages []ChatMessage) (string, error) {
	var msgParams []openai.ChatCompletionMessageParamUnion

	systemBlock := []openai.ChatCompletionMessageParamUnion{
		{
			OfSystem: &openai.ChatCompletionSystemMessageParam{
				Content: openai.ChatCompletionSystemMessageParamContentUnion{
					OfString: openai.String(systemPrompt),
				},
			},
		},
	}

	msgParams = append(msgParams, systemBlock...)

	for _, m := range messages {
		switch m.Role {
		case "assistant":
			msgParams = append(msgParams, openai.ChatCompletionMessageParamUnion{
				OfAssistant: &openai.ChatCompletionAssistantMessageParam{
					Content: openai.ChatCompletionAssistantMessageParamContentUnion{
						OfString: openai.String(m.Content),
					},
				},
			})
		case "system":
			msgParams = append(msgParams, openai.ChatCompletionMessageParamUnion{
				OfSystem: &openai.ChatCompletionSystemMessageParam{
					Content: openai.ChatCompletionSystemMessageParamContentUnion{
						OfString: openai.String(m.Content),
					},
				},
			})
		default: // user
			msgParams = append(msgParams, openai.ChatCompletionMessageParamUnion{
				OfUser: &openai.ChatCompletionUserMessageParam{
					Content: openai.ChatCompletionUserMessageParamContentUnion{
						OfString: openai.String(m.Content),
					},
				},
			})
		}
	}

	resp, err := c.client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Model:               shared.ChatModel(c.model),
		Messages:            msgParams,
		MaxCompletionTokens: openai.Int(MAX_TOKENS_OPENAI),
	})
	if err != nil {
		return "", err
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("LLM response contained no choices")
	}

	// Extract content from the message
	msg := resp.Choices[0].Message
	if msg.Content == "" {
		return "", fmt.Errorf("LLM returned empty content in message")
	}
	return msg.Content, nil
}
