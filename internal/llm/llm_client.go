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

const (
	OutputFormatJSON = 0
	OutputFormatYAML = 1
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
func (c *LLMClient) CallLLM(ctx context.Context, userPrompt string, outputFormat int) (string, error) {
	systemPrompt := `You are a security analyst specializing in analyzing API tools and schemas for security vulnerabilities. 
Analyze the provided tool information and return a JSON array of security findings.
Each finding must have: severity, rule_id, title, message, and optionally category.
Return ONLY valid JSON, no markdown formatting, no code fences.`
	if outputFormat == OutputFormatYAML {
		systemPrompt = `You are a security analyst specializing in analyzing API tools and schemas for security vulnerabilities. 
Analyze the provided tool information and return a YAML object of security findings.
Each finding must have: severity, rule_id, title, message, and optionally category.
Return ONLY valid YAML, no markdown formatting, no code fences.`
	}

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
	if len(preview) > 1000 {
		preview = preview[:1000] + "..."
	}
	fmt.Printf("LLM response (first 1000 bytes): \n%s\n", preview)

	// Strip markdown code fences if present - use the specified format
	content = c.stripMarkdownCodeFences(content, outputFormat)

	// Check again after trimming
	if content == "" {
		return "", fmt.Errorf("LLM response is empty after trimming markdown")
	}

	return content, nil
}

// stripMarkdownCodeFences removes markdown code fences from the content
// Uses the specified outputFormat to determine which handler to use
func (c *LLMClient) stripMarkdownCodeFences(content string, outputFormat int) string {
	content = strings.TrimSpace(content)

	// Use the specified format instead of auto-detection
	if outputFormat == OutputFormatYAML {
		fmt.Printf("Content is YAML\n")
		return c.stripYAMLCodeFences(content)
	}

	fmt.Printf("Content is JSON\n")
	return c.stripJSONCodeFences(content)
}

// stripYAMLCodeFences removes markdown code fences from YAML content
// YAML should not be extracted by braces since it may contain ${VAR} references
func (c *LLMClient) stripYAMLCodeFences(content string) string {
	content = strings.TrimSpace(content)

	// Remove opening code fences with language specifier (```yaml or ```yml)
	content = strings.TrimPrefix(content, "```yaml")
	content = strings.TrimPrefix(content, "```yml")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSpace(content)

	// Handle case where "yaml" or "yml" appears on its own line (without backticks)
	// This can happen when LLM generates just the language identifier
	if strings.HasPrefix(content, "yaml\n") {
		content = strings.TrimPrefix(content, "yaml\n")
	} else if strings.HasPrefix(content, "yaml\r\n") {
		content = strings.TrimPrefix(content, "yaml\r\n")
	} else if strings.HasPrefix(content, "yml\n") {
		content = strings.TrimPrefix(content, "yml\n")
	} else if strings.HasPrefix(content, "yml\r\n") {
		content = strings.TrimPrefix(content, "yml\r\n")
	} else if content == "yaml" {
		// If content is just "yaml", return empty (shouldn't happen but handle it)
		return ""
	}
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
// Handles both JSON objects {} and JSON arrays []
func (c *LLMClient) stripJSONCodeFences(content string) string {
	content = strings.TrimSpace(content)

	// First, try to find JSON array content by looking for [ and ]
	// This handles arrays like [{...}] which are common in API responses
	firstBracket := strings.Index(content, "[")
	lastBracket := strings.LastIndex(content, "]")

	// Also check for JSON objects
	firstBrace := strings.Index(content, "{")
	lastBrace := strings.LastIndex(content, "}")

	// Prefer arrays if both are present and array brackets are outermost
	// or if array starts before object
	if firstBracket != -1 && lastBracket != -1 && lastBracket > firstBracket {
		// Check if array brackets encompass the object braces (or if no object braces)
		if firstBrace == -1 || (firstBracket <= firstBrace && lastBracket >= lastBrace) {
			// Extract the array portion
			content = content[firstBracket : lastBracket+1]
			return content
		}
	}

	// Fall back to object extraction if array not found or object is outermost
	if firstBrace != -1 && lastBrace != -1 && lastBrace > firstBrace {
		// Extract just the JSON object portion
		content = content[firstBrace : lastBrace+1]
		return content
	}

	// Fallback to string manipulation if JSON braces/brackets not found
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

	return content
}
