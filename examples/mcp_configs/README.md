# MCP config examples

## Figma (remote HTTP)

Figma's remote MCP server (`https://mcp.figma.com/mcp`) does not support Dynamic Client Registration (DCR). To connect you need a pre-registered OAuth client:

1. **Get a client ID** – Request access via [Figma's MCP client request form](https://form.asana.com/?k=kBG-ejRQTdY8x_H6a4vM3Q&d=10497086658021). Use the `client_id` they provide.
2. **Add to config** – Set `oauth_client_id` (and `oauth_client_secret` if provided) on the server entry:

```json
{
  "mcpServers": {
    "figma": {
      "type": "http",
      "url": "https://mcp.figma.com/mcp",
      "oauth_client_id": "YOUR_CLIENT_ID"
    }
  }
}
```

Without `oauth_client_id`, the tool continues without authentication and Figma will reject MCP requests that require auth.

## AUTH-MISSING and `protected_tools`

The AUTH-MISSING pentest calls the tool again with no configured header and no OAuth token. A 401 or 403 is a pass. A tool that still answers is listed for review, because mcpxray cannot tell a public tool from an unprotected one. List the tools that must require credentials under `protected_tools`; when one of them answers without credentials, it is reported as a HIGH finding.

```json
{
  "mcpServers": {
    "my-server": {
      "type": "http",
      "url": "https://example.com/mcp",
      "headers": { "Authorization": "Bearer YOUR_TOKEN" },
      "protected_tools": ["list_calls"]
    }
  }
}
```
