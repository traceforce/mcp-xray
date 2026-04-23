package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

type BedrockLlamaClient struct {
	client              *bedrockruntime.Client
	inferenceProfileArn string
}

var _ ChatClient = (*BedrockLlamaClient)(nil)

type BedrockLlamaRequest struct {
	Prompt    string `json:"prompt"`
	MaxGenLen int    `json:"max_gen_len"`
}

type BedrockLlamaResponse struct {
	Generation           string `json:"generation"`
	PromptTokenCount     int    `json:"prompt_token_count"`
	GenerationTokenCount int    `json:"generation_token_count"`
	StopReason           string `json:"stop_reason"`
}

func NewBedrockLlamaClient(cfg aws.Config, inferenceProfileArn string, maxRetries int) *BedrockLlamaClient {
	return &BedrockLlamaClient{
		client: bedrockruntime.NewFromConfig(cfg, func(o *bedrockruntime.Options) {
			// RetryMaxAttempts is total attempts (1 = no retry); the CLI flag counts retries, so add 1.
			o.RetryMaxAttempts = maxRetries + 1
		}),
		inferenceProfileArn: inferenceProfileArn,
	}
}

func (c *BedrockLlamaClient) Chat(ctx context.Context, systemPrompt string, messages []ChatMessage) (string, error) {

	reqMessage := systemPrompt + "\n\n"
	for _, message := range messages {
		reqMessage += message.Content + "\n\n"
	}

	reqBody := BedrockLlamaRequest{
		Prompt:    reqMessage,
		MaxGenLen: MAX_TOKENS_AWS,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	// Build the InvokeModelInput with either ModelId or InferenceProfileId
	input := &bedrockruntime.InvokeModelInput{
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
		Body:        bodyBytes,
	}

	if c.inferenceProfileArn != "" {
		// Use inference profile ARN if provided
		input.ModelId = aws.String(c.inferenceProfileArn)
	} else {
		return "", fmt.Errorf("inference profile ARN must be provided")
	}

	out, err := c.client.InvokeModel(ctx, input)
	if err != nil {
		return "", err
	}

	var br BedrockLlamaResponse
	if err := json.Unmarshal(out.Body, &br); err != nil {
		return "", err
	}

	if br.Generation == "" {
		return "", fmt.Errorf("LLM returned empty generation content")
	}

	return br.Generation, nil
}
