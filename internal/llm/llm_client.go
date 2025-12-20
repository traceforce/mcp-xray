package llm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/joho/godotenv"
)

const (
	LLM_TYPE_UNKNOWN   = 0
	LLM_TYPE_ANTHROPIC = 1
	LLM_TYPE_OPENAI    = 2
	LLM_TYPE_AWS       = 3
)

type LLMClient struct {
	ChatClient ChatClient
	llmType    int
	timeout    time.Duration
}

const (
	MAX_TOKENS_ANTHROPIC = 12000
	MAX_TOKENS_OPENAI    = 12000
	MAX_TOKENS_AWS       = 2048
)

// NewLLMClientFromEnvWithModel creates a new LLM client from environment variables
func NewLLMClientFromEnvWithModel(model string, timeout time.Duration) (*LLMClient, error) {
	if model == "" {
		return nil, errors.New("model is required")
	}

	// Try to load environment variables from .env file.Ignores error if .env doesn't exist as we
	// will try to load from the enviornment variables directly
	_ = godotenv.Load()

	llmType := LLM_TYPE_UNKNOWN
	var chatClient ChatClient
	if strings.HasPrefix(strings.ToLower(model), "claude-") {
		llmType = LLM_TYPE_ANTHROPIC
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			return nil, errors.New("To use Anthropic models, the Environment variable ANTHROPIC_API_KEY is required")
		}
		chatClient = NewAnthropicClient(apiKey, model)
	} else if strings.HasPrefix(strings.ToLower(model), "gpt-") {
		llmType = LLM_TYPE_OPENAI
		apiKey := os.Getenv("OPENAI_API_KEY")
		if apiKey == "" {
			return nil, errors.New("To use OpenAI models, the Environment variable OPENAI_API_KEY is required")
		}
		chatClient = NewOpenAIClient(apiKey, model)
	} else if strings.HasPrefix(strings.ToLower(model), "arn:aws:bedrock:") && strings.Contains(strings.ToLower(model), "llama") {
		llmType = LLM_TYPE_AWS
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, fmt.Errorf("To use AWS models, the AWS config must be loaded: %w", err)
		}
		chatClient = NewBedrockLlamaClient(cfg, model)
	} else {
		example := "arn:aws:bedrock:us-east-2:522814721969:inference-profile/us.meta.llama3-2-1b-instruct-v1:0"
		return nil, fmt.Errorf("Unsupported LLM model: %v. If you are using an AWS model, it must be an Meta Llama inference profile ARN starting with 'arn:aws:bedrock:' (e.g. %v)", model, example)
	}

	return &LLMClient{
		ChatClient: chatClient,
		llmType:    llmType,
		timeout:    timeout,
	}, nil
}

// GetType returns the LLM type
func (c *LLMClient) GetType() int {
	return c.llmType
}

// callLLM calls the LLM API
func (c *LLMClient) CallLLM(ctx context.Context, userPrompt string) (string, error) {
	systemPrompt := `You are a security analyst specializing in analyzing API tools and schemas for security vulnerabilities. 
Analyze the provided tool information and return a JSON array of security findings.
Each finding must have: severity, rule_id, title, message, and optionally category.
Return ONLY valid JSON, no markdown formatting, no code fences.`

	content, err := c.ChatClient.Chat(ctx, systemPrompt, []ChatMessage{
		{Role: "user", Content: userPrompt},
	})
	if err != nil {
		return "", err
	}

	// Check if response is empty
	if content == "" {
		return "", fmt.Errorf("LLM returned empty response")
	}

	// Print first 200 bytes for debugging
	preview := content
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}
	fmt.Printf("LLM response (first 200 bytes): %s\n", preview)

	// Strip markdown code fences if present - handle various formats
	content = c.stripMarkdownCodeFences(content)

	// Check again after trimming
	if content == "" {
		return "", fmt.Errorf("LLM response is empty after trimming markdown")
	}

	return content, nil
}

// stripMarkdownCodeFences removes markdown code fences from the content
// Detects content type (JSON vs YAML) and calls the appropriate handler
func (c *LLMClient) stripMarkdownCodeFences(content string) string {
	content = strings.TrimSpace(content)

	// Detect content type
	if c.isYAMLContent(content) {
		fmt.Printf("Content is YAML\n")
		return c.stripYAMLCodeFences(content)
	}

	fmt.Printf("Content is JSON\n")
	return c.stripJSONCodeFences(content)
}

// isYAMLContent determines if the content is YAML based on common YAML patterns
func (c *LLMClient) isYAMLContent(content string) bool {
	// Remove markdown code fences for detection
	trimmed := content
	trimmed = strings.TrimPrefix(trimmed, "ml")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)

	// Check for YAML indicators
	return strings.HasPrefix(trimmed, "metadata:") ||
		strings.HasPrefix(trimmed, "tests:") ||
		strings.HasPrefix(trimmed, "test_id:") ||
		strings.HasPrefix(trimmed, "version:") ||
		(strings.Contains(trimmed, ":\n") && !strings.HasPrefix(trimmed, "{"))
}

// stripYAMLCodeFences removes markdown code fences from YAML content
// YAML should not be extracted by braces since it may contain ${VAR} references
func (c *LLMClient) stripYAMLCodeFences(content string) string {
	content = strings.TrimSpace(content)

	// Remove opening code fences (with or without language specifier)
	content = strings.TrimPrefix(content, "ml")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSpace(content)

	// Remove closing code fences (handle multiple cases)
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	// Remove any remaining standalone backticks
	content = strings.ReplaceAll(content, "```", "")
	content = strings.TrimSpace(content)

	return content
}

// stripJSONCodeFences removes markdown code fences from JSON content
// Handles various formats: ```json, ```, with or without newlines
func (c *LLMClient) stripJSONCodeFences(content string) string {
	content = strings.TrimSpace(content)

	// Try to find JSON content by looking for the first { and last }
	// This handles cases where there might be text or backticks before/after
	firstBrace := strings.Index(content, "{")
	lastBrace := strings.LastIndex(content, "}")

	if firstBrace != -1 && lastBrace != -1 && lastBrace > firstBrace {
		// Extract just the JSON portion
		content = content[firstBrace : lastBrace+1]
	} else {
		// Fallback to string manipulation if JSON braces not found
		// Remove opening code fences (with or without language specifier)
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSpace(content)

		// Remove closing code fences (handle multiple cases)
		content = strings.TrimSuffix(content, "```")
		content = strings.TrimSpace(content)

		// Remove any remaining standalone backticks
		content = strings.ReplaceAll(content, "```", "")
		content = strings.TrimSpace(content)
	}

	return content
}
