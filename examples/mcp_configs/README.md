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

## Pentest `auth_policy` (AUTH-MISSING)

AUTH-MISSING sends a tool a second call without the configured Authorization header only when the tool is listed under `repeatable`. A `protected` tool must reject that call; a `public` tool is skipped; a tool in neither list is reported for review.

```json
{
  "mcpServers": {
    "example": {
      "type": "http",
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer YOUR_TOKEN" },
      "auth_policy": { "protected": ["list_calls"], "public": ["health"], "repeatable": ["list_calls"] }
    }
  }
}
```
