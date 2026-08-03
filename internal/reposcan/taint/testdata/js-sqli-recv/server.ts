// Precision fixture for the sqli receiver constraint (V43-5).
//
// The review said matching `.query()`/`.execute()`/`.raw()` on ANY receiver reports a job
// queue, a query-string builder, or any custom class as HIGH SQL injection. Constraining
// the receiver fixes that -- but a constraint that is too tight deletes real sinks instead,
// which for a security scanner is the worse failure. This fixture pins BOTH directions.
//
// MUST be reported:     t_db_var, t_pool, t_this_db
// MUST NOT be reported: t_queue, t_urlbuilder, t_custom
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Pool } from "pg";

const server = new McpServer({ name: "recv", version: "1.0.0" });
const db = new Pool();
const pool = new Pool();

server.tool("t_db_var", async (args: any) => {
  return db.query("SELECT * FROM t WHERE a = '" + args.q + "'");
});

server.tool("t_pool", async (args: any) => {
  return pool.query("SELECT * FROM t WHERE a = '" + args.q + "'");
});

// The class-based shape. `this.db` is a PropAccess, not a VarAccess -- the receiver
// name fallback missed it until dbHandleName was applied to property reads too.
class Service {
  private db = new Pool();
  register(s: McpServer) {
    s.tool("t_this_db", async (args: any) => {
      return this.db.query("SELECT * FROM t WHERE a = '" + args.q + "'");
    });
  }
}

// A job queue's execute -- the review's example. Not a database sink.
const queue = { execute: (s: string) => s };
server.tool("t_queue", async (args: any) => {
  return queue.execute(args.q);
});

// A query-string builder's query. Not a database sink.
const urlbuilder = { query: (s: string) => s };
server.tool("t_urlbuilder", async (args: any) => {
  return urlbuilder.query(args.q);
});

// An unrelated custom class exposing raw(). Not a database sink.
class Reporter {
  raw(s: string) {
    return s;
  }
}
const reporter = new Reporter();
server.tool("t_custom", async (args: any) => {
  return reporter.raw(args.q);
});

export { Service };
