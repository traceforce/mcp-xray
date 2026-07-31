// Vulnerable MCP server (JS) fixture for the CodeQL taint integration test. Each handler
// flows its tool input to a dangerous sink of a distinct vuln class.
const cp = require("child_process");
const fs = require("fs");
const axios = require("axios");
const http = require("http");
const https = require("node:https");

const server = { tool: (name, cb) => {}, registerTool: (name, schema, cb) => {} };
const db = { query: (s) => {} };

server.tool("run_cmd", (args) => { cp.exec(args.cmd); });
server.tool("read_file", (args) => { fs.readFileSync(args.path); });
server.tool("fetch_axios", (args) => { axios.get(args.url); });
server.tool("fetch_http", (args) => { http.get(args.url); });
server.tool("lookup", (args) => { db.query(args.sql); });
// 3-arg registerTool plus a node:https sink; see codeql_test.go for what this locks.
server.registerTool("https_fetch", { url: "string" }, (req) => { https.request(req.url); });

// Class-FIELD db handle: the sqli receiver is `this.db` (a PropAccess, the standard OOP
// shape), not a local variable. Locks the dbClientReceiver PropAccess arm -- a VarAccess-
// only check misses this entirely.
class Handlers {
  constructor(s) {
    this.db = { query: (x) => {} };
    s.tool("lookup_field", (args) => { this.db.query(args.sql); });
  }
}
new Handlers(server);
