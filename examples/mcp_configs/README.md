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

## AUTH-MISSING

The AUTH-MISSING pentest opens a separate HTTP/SSE session with no configured headers or OAuth token. Only HTTP 401 or 403 from the probe proves authentication was refused. Tool errors and successful anonymous calls require review and make the assessment incomplete; they do not establish an authentication bypass or prove enforcement. Business prerequisites do not block this independent probe.
