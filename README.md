# SecureMCP

A comprehensive open-source security auditing tool for Model Context Protocol (MCP) servers. Generates production-ready [SARIF reports](https://sarifweb.azurewebsites.net/) for seamless integration with security tooling and CI/CD pipelines.

## Overview

SecureMCP performs security analysis on MCP (Model Context Protocol) servers and their codebases. It scans for security issues across multiple dimensions including configuration vulnerabilities, exposed secrets, unsafe tool definitions, and code-level security problems.

## Features

### Configuration Scanning (`config-scan`)

Analyzes MCP server configurations for security issues. Designed to be run before you deploy any configuration to production services.

- **Connection Security**: Validates HTTP/HTTPS connections, TLS configuration, and authentication mechanisms
- **Tool Analysis**: Analyzes tool definitions for security risks using either:
  - **Token Analyzer** (default): Fast, rule-based pattern matching that detects:
    - Destructive commands
    - Command injection and arbitrary tool execution
    - Unvalidated user input
    - Insecure permission assignments
    - Active connection leaks
    - Information disclosure risks
  - **LLM Analyzer**: Deep semantic analysis using large language models to detect:
    - Arbitrary tool execution without validation
    - Insufficient input validation on tool arguments
    - Missing authorization or permission checks
    - Code injection and repository modification
    - Privilege escalation and access control bypass
    - Credential exposure and connection hijacking
    - Information disclosure and reconnaissance
- **Secrets Detection**: Scans configuration files for exposed credentials, API keys, and other sensitive information using Gitleaks

### Repository Scanning (`repo-scan`)

Performs comprehensive security analysis of the MCP server codebase. Designed for custom MCP servers before adding them to configurations.

- **SCA (Software Composition Analysis)**: Detects vulnerable dependencies using OSV Scanner
- **SAST (Static Application Security Testing)**: Identifies unsafe command patterns and security anti-patterns in code
- **Secrets Detection**: Scans source code for hardcoded secrets and credentials using Gitleaks

## Installation

### Prerequisites

- [Go 1.25.4 or later](https://go.dev/dl/)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/traceforce/SecureMCP
cd SecureMCP

# Install required dependencies (buf, etc.)
make install-dependencies

# Build everything (generates protobuf code and builds the binary)
# The binary will be created as `securemcp` in the current directory
make all

```

Alternatively, you can build individual components:

```bash
# Generate protocol buffers only
make proto

# Build the binary only (requires proto to be generated first)
make build
```

## Usage

### Configuration Scan

Scan MCP server configurations for security issues:

```bash
# Scan a specific MCP config file (uses token analyzer by default)
./securemcp config-scan /path/to/mcp/config.json

# Use token analyzer explicitly (fast, rule-based)
./securemcp config-scan /path/to/mcp/config.json --analyzer-type token

# Use LLM analyzer for more extensive and deepr analysis
./securemcp config-scan /path/to/mcp/config.json --analyzer-type llm --llm-model claude-3-5-sonnet-20241022

# Specify custom output file
./securemcp config-scan /path/to/mcp/config.json --output custom-report.sarif.json
```

The configuration scanner will:
1. Parse MCP server configuration files
2. Analyze connection security (HTTP/HTTPS, TLS, authentication)
3. Discover and analyze available tools from MCP servers using the selected analyzer
4. Scan for exposed secrets in configuration files

### Repository Scan

Scan the codebase for security vulnerabilities:

```bash
# Scan current directory
./securemcp repo-scan

# Scan a specific repository
./securemcp repo-scan /path/to/repository

# Specify custom output file
./securemcp repo-scan --output custom-report.sarif.json
```

The repository scanner will:
1. Perform SCA analysis to detect vulnerable dependencies
2. Run SAST analysis to identify unsafe code patterns using YARA rules
3. Scan for hardcoded secrets and credentials in source code

## Output Format

SecureMCP generates reports in [SARIF (Static Analysis Results Interchange Format)](https://sarifweb.azurewebsites.net/) format, which is widely supported by security tools and CI/CD platforms.

## Examples

Example scan outputs are available in `examples/findings/`:

- `config-scan-risky-tools.sarif.json`: Configuration scan findings for tools with high security risks
- `config-scan-secrets.sarif.json`: Configuration scan findings for secrets exposed in configurations
- `repo-scan-cve-secrets.sarif.json`: Repository scan findings for CVE vulnerabilities and secrets
- `repo-scan-dangerous-commands.sarif.json`: Repository scan findings for dangerous command patterns

Example MCP configuration files are available in the `examples/mcp_configs/` directory:

- `local_mcp.json`: Local STDIO-based MCP server
- `remote_mcp_token.json`: Remote HTTP server with token authentication
- `remote_mcp_oauth.json`: Remote HTTP server with OAuth authentication
- `mcp_with_env.json`: Configuration using environment variables
- `mcp_with_proxy.json`: Configuration with proxy settings

An example MCP Server is available in the `examples/mcp_server/` directory:
- `mcp_server.py`: FastMCP server using streamable-http transport
- `mcp.json`: Configuration file for connecting to the server
- `README.md`: Instructions for setting up and scanning the server

## Configuration

### Tool Analysis Methods

SecureMCP provides two methods for analyzing tool security:

#### Token Analyzer (Default)

The token analyzer uses rule-based pattern matching to quickly detect security issues in tool descriptions. It's fast, doesn't require API keys, and works offline. Token analyzer uses two types of rules:
1. **Token rules** are defined in `internal/configscan/tokenanalyzer/token_rules.yaml`. Each rule specifies:
   - Pattern matching criteria (tokens and phrases)
   - Severity level (low, medium, high, critical)
   - Security category and reason
2. **YARA rules** are defined in `internal/yararules/unsafe_patterns.yar`. These rules detect unsafe system command patterns such as:
   - Destructive file operations
   - System security bypass attempts
   - Remote code execution patterns
   - Privilege escalation attempts
   - And other dangerous system operations

**Usage:**
```bash
securemcp config-scan --analyzer-type token
```

#### LLM Analyzer

The LLM analyzer uses large language models for deep semantic analysis of tool descriptions, providing more comprehensive security insights.

**Usage:**
```bash
securemcp config-scan --analyzer-type llm --llm-model <model-name>
```

### Supported Models

SecureMCP supports the following LLM providers for tool analysis:

#### Anthropic (Claude)
- Examples: `claude-sonnet-4-5`
- Requires: `ANTHROPIC_API_KEY` environment variable

#### OpenAI (GPT)
- Examples: `gpt-5`
- Requires: `OPENAI_API_KEY` environment variable

#### AWS Bedrock (Meta Llama)
- Meta Llama inference profile ARNs starting with `arn:aws:bedrock:` and containing `llama`
- Example: `arn:aws:bedrock:<region>:<account-id>:inference-profile/us.meta.llama3-2-1b-instruct-v1:0`
- Requires: AWS credentials configured via AWS SDK (environment variables, IAM role, or credentials file)

### Environment Variables

For LLM-based tool analysis, configure your LLM API credentials:

#### Anthropic
```bash
export ANTHROPIC_API_KEY=your-api-key
```

#### OpenAI
```bash
export OPENAI_API_KEY=your-api-key
```

Each provider requires its own specific environment variable. The tool automatically detects which provider to use based on the model name.

#### AWS Bedrock
For AWS Bedrock models, configure AWS credentials using one of the standard AWS SDK methods:

```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_REGION=us-east-1

# Option 2: AWS credentials file (~/.aws/credentials)
# Option 3: IAM role (when running on EC2/ECS/Lambda)
```

SecureMCP uses AWS SDK that will automatically load credentials from the environment, credentials file, or IAM role.

## Contributing

Contributions are welcome! Please ensure that:

1. Code follows Go best practices
2. Tests and examples are included for new features
3. Documentation is updated

## References

- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [OSV Scanner](https://google.github.io/osv-scanner/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
