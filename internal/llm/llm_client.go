package llm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/anthropic"
	"github.com/tmc/langchaingo/llms/openai"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
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
	model   llms.Model
	llmType int
	timeout time.Duration
}

const (
	MAX_TOKENS = 12000
)

// resolveAPIKey checks environment variables, then the OS keyring.
// If neither is found, it interactively prompts the user, then saves to the keyring.
func resolveAPIKey(providerName string, envVarName string) (string, error) {
	// 1. Check environment variable
	if key := os.Getenv(envVarName); key != "" {
		return key, nil
	}

	// 2. Check OS keyring
	key, err := keyring.Get("mcpxray", providerName)
	if err == nil && key != "" {
		return key, nil
	}

	// 3. Interactively prompt
	fmt.Printf("API Key for %s (%s) not found in environment or keyring.\n", providerName, envVarName)
	fmt.Printf("Please enter your API Key: ")

	// Read securely if it's a terminal, otherwise fallback
	var input string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		input = string(bytePassword)
		fmt.Println() // Print newline after hidden input
	} else {
		_, err := fmt.Scanln(&input)
		if err != nil {
			return "", fmt.Errorf("failed to read input: %w", err)
		}
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return "", errors.New("empty API key provided")
	}

	// 4. Save to keyring
	err = keyring.Set("mcpxray", providerName, input)
	if err != nil {
		fmt.Printf("Warning: Failed to save key to keyring: %v\n", err)
	} else {
		fmt.Printf("Successfully saved %s API key to secure keyring.\n", providerName)
	}

	return input, nil
}

// NewLLMClientFromEnvWithModel creates a new LLM client using langchaingo
func NewLLMClientFromEnvWithModel(model string, timeout time.Duration, maxRetries int) (*LLMClient, error) {
	if model == "" {
		return nil, errors.New("model is required")
	}

	_ = godotenv.Load()

	var llmModel llms.Model
	var err error
	llmType := LLM_TYPE_UNKNOWN

	if strings.HasPrefix(strings.ToLower(model), "claude-") {
		llmType = LLM_TYPE_ANTHROPIC
		apiKey, resolveErr := resolveAPIKey("Anthropic", "ANTHROPIC_API_KEY")
		if resolveErr != nil {
			return nil, resolveErr
		}
		llmModel, err = anthropic.New(
			anthropic.WithModel(model),
			anthropic.WithToken(apiKey),
		)
	} else if strings.HasPrefix(strings.ToLower(model), "gpt-") || strings.HasPrefix(strings.ToLower(model), "o1-") {
		llmType = LLM_TYPE_OPENAI
		apiKey, resolveErr := resolveAPIKey("OpenAI", "OPENAI_API_KEY")
		if resolveErr != nil {
			return nil, resolveErr
		}
		llmModel, err = openai.New(
			openai.WithModel(model),
			openai.WithToken(apiKey),
		)
	} else {
		return nil, fmt.Errorf("Unsupported LLM model provider prefix: %v", model)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize langchaingo client: %w", err)
	}

	return &LLMClient{
		model:   llmModel,
		llmType: llmType,
		timeout: timeout,
	}, nil
}

// GetType returns the LLM type
func (c *LLMClient) GetType() int {
	return c.llmType
}

// CallLLM calls the LLM API using langchaingo
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

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	messages := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, userPrompt),
	}

	resp, err := c.model.GenerateContent(ctx, messages, llms.WithMaxTokens(MAX_TOKENS))
	if err != nil {
		return "", err
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("LLM returned no choices")
	}

	content := resp.Choices[0].Content
	if content == "" {
		return "", fmt.Errorf("LLM returned empty response")
	}

	// Print first 200 bytes for debugging
	preview := content
	if len(preview) > 1000 {
		preview = preview[:1000] + "..."
	}
	fmt.Printf("LLM response (first 1000 bytes): \n%s\n", preview)

	content = c.stripMarkdownCodeFences(content, outputFormat)

	if outputFormat == OutputFormatYAML {
		content = sanitizeYAMLUnicodeEscapes(content)
	}

	if content == "" {
		return "", fmt.Errorf("LLM response is empty after trimming markdown")
	}

	return content, nil
}

// invalidUnicodeEscape matches YAML \uXXXX escapes for surrogate code points (U+D800–U+DFFF),
// which are invalid in UTF-8 and cause gopkg.in/yaml to fail with "invalid Unicode character escape code".
var invalidUnicodeEscape = regexp.MustCompile(`\\uD[89A-Fa-f][0-9A-Fa-f]{2}|\\uD[C-Fc-f][0-9A-Fa-f]{2}`)

// sanitizeYAMLUnicodeEscapes replaces invalid Unicode escape sequences (unpaired surrogates
// U+D800–U+DFFF) with the replacement character U+FFFD so YAML parsers can decode the content.
func sanitizeYAMLUnicodeEscapes(yamlContent string) string {
	return invalidUnicodeEscape.ReplaceAllString(yamlContent, `\uFFFD`)
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
