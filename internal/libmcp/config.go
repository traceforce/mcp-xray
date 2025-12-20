package libmcp

import (
	"encoding/json"
	"fmt"
	"os"
)

// RawConfig is the raw configuration from the file. It's compatible with Cursor, Windsurf and Claude
type RawConfig struct {
	McpServers map[string]RawServerConfig `json:"mcpServers"`
}

type RawServerConfig struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	URL     string            `json:"url,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Type    string            `json:"type,omitempty"`
}

type ConfigParser struct {
	configPath string
}

func NewConfigParser(filePath string) *ConfigParser {
	return &ConfigParser{
		configPath: filePath,
	}
}

func (c *ConfigParser) Parse() ([]MCPServerConfig, error) {
	data, err := os.ReadFile(c.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return ParseConfig(data)
}

// ParseConfig parses MCP config from raw bytes
func ParseConfig(data []byte) ([]MCPServerConfig, error) {
	var config RawConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse MCP config: %w", err)
	}

	// Parse raw data once for all servers
	var rawData map[string]interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		return nil, fmt.Errorf("failed to parse raw data: %w", err)
	}

	var servers []MCPServerConfig
	for serverName, serverConfig := range config.McpServers {
		var command *string
		var url *string
		var transportType *string

		if serverConfig.Command != "" {
			command = &serverConfig.Command
		}
		if serverConfig.URL != "" {
			url = &serverConfig.URL
		}
		if serverConfig.Type != "" {
			transportType = &serverConfig.Type
		}

		// Extract raw JSON for this specific server from original data
		var rawJSON string
		if mcpServers, ok := rawData["mcpServers"].(map[string]interface{}); ok {
			if serverData, ok := mcpServers[serverName]; ok {
				if rawBytes, err := json.Marshal(serverData); err == nil {
					rawJSON = string(rawBytes)
				}
			}
		}

		server := MCPServerConfig{
			Name:    serverName,
			Command: command,
			Args:    serverConfig.Args,
			URL:     url,
			Env:     serverConfig.Env,
			Headers: serverConfig.Headers,
			Type:    transportType,
			RawJSON: string(rawJSON),
		}
		servers = append(servers, server)
	}

	return servers, nil
}
