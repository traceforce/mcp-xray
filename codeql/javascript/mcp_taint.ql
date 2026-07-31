/**
 * @name MCP handler input reaches a dangerous sink (JS/TS, interprocedural)
 * @description Deterministic taint detection for JavaScript/TypeScript MCP servers.
 *              Sources are the parameters of MCP tool/resource handler callbacks
 *              (server.tool(...), registerTool(...), setRequestHandler(...)) plus the
 *              low-level request.params.arguments object; sinks are a static per-class
 *              list. CodeQL provides the interprocedural, cross-file dataflow. The
 *              matched class is tagged MCP-TAINT[<class>] and the precise sink API is
 *              emitted as sink=<api> so the pipeline recovers both deterministically
 *              from a single analyze run.
 * @kind path-problem
 * @id mcp/taint-js
 * @problem.severity error
 * @tags security
 */

import javascript
import semmle.javascript.ApiGraphs

/**
 * Holds if `source` is attacker-controlled MCP tool input: a parameter of the
 * callback registered with an MCP tool/resource API, or a `*.params.arguments`
 * read (the low-level CallToolRequest input).
 */
predicate isMcpSource(DataFlow::Node source) {
  exists(DataFlow::MethodCallNode reg |
    // registerResource is the documented resource API on the current McpServer surface,
    // and prompt/registerPrompt are its prompt equivalents. Without them, modern
    // resource and prompt handlers produce no sources at all -- silent zero coverage
    // for a whole handler category. The #44 adapter's reRegBoundary/reRegName want the
    // same names, or the query finds a source the adapter cannot attribute.
    reg.getMethodName() =
      [
        "tool", "registerTool", "resource", "registerResource", "prompt",
        "registerPrompt", "setRequestHandler"
      ] and
    source = reg.getABoundCallbackParameter(_, _)
  )
  or
  exists(DataFlow::PropRead args |
    args.getPropertyName() = "arguments" and
    args.getBase().(DataFlow::PropRead).getPropertyName() = "params" and
    source = args
  )
}

/**
 * Holds if `node` is a dangerous sink argument for vuln class `cls`, reached via the
 * sink API `api` (the `<module>.<fn>` the query matched). `api` is emitted in the
 * result so the pipeline records the precise sink deterministically rather than
 * re-deriving it from a snippet. Static per-class lists; CodeQL still requires taint
 * to actually reach them, so a broad list does not create false positives.
 */
/**
 * Holds if `node` is (or derives from) a client object created by a known SQL package, so
 * a `.query()`/`.execute()`/`.raw()` on it is a genuine database sink rather than a
 * same-named method on an unrelated object.
 */
/**
 * A name conventionally given to a database handle, whether a local variable (`db`) or a
 * class field (`this.db`). A job queue is `queue`/`jobs` and a query-string builder is
 * `url`/`params`, so the noise Varun described stays excluded.
 */
predicate dbHandleName(string n) {
  n =
    [
      "db", "pool", "conn", "connection", "client", "knex", "sequelize", "prisma", "sql",
      "database", "datasource"
    ]
}

predicate dbClientReceiver(DataFlow::Node node) {
  // Preferred: the receiver demonstrably flows from a known SQL package.
  exists(API::Node db |
    db =
      API::moduleImport([
          "pg", "mysql", "mysql2", "mysql2/promise", "sqlite3", "better-sqlite3",
          "knex", "sequelize", "typeorm", "mssql", "oracledb", "@prisma/client",
          "postgres", "pg-promise", "drizzle-orm"
        ]).getAMember*() and
    node = db.getAValueReachableFromSource()
  )
  or
  // Fallback on the receiver's NAME. Import-tracking alone is too strict in practice: the
  // handle is very often constructed in one module and imported into the tool file
  // (`import { db } from "./db"`), where the flow to the package is not visible; requiring
  // the import would trade Varun's false positives for false NEGATIVES -- the worse trade
  // for a scanner. Cover both a local variable (`db.query(...)`) and a class FIELD
  // (`this.db.query(...)`, `this.pool.execute(...)`) -- the standard OOP handler shape,
  // whose receiver is a PropAccess, not a VarAccess, and was previously missed entirely.
  dbHandleName(node.asExpr().(VarAccess).getName().toLowerCase())
  or
  dbHandleName(node.asExpr().(PropAccess).getPropertyName().toLowerCase())
}

predicate dangerousSink(DataFlow::Node node, string cls, string api) {
  cls = "command_injection" and
  exists(string m |
    m = ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"] and
    node =
      API::moduleImport(["child_process", "node:child_process"]).getMember(m).getACall().getArgument(0) and
    api = "child_process." + m
  )
  or
  // eval runs attacker input as code -- code injection (INJECTION-CODE), matching the
  // opengrep/CodeQL-python taxonomy rather than command injection.
  cls = "code_injection" and
  node = DataFlow::globalVarRef("eval").getACall().getArgument(0) and
  api = "eval"
  or
  cls = "path_traversal" and
  exists(string m |
    m =
      [
        "readFile", "readFileSync", "writeFile", "writeFileSync", "open", "openSync",
        "createReadStream", "createWriteStream", "unlink", "unlinkSync", "appendFile",
        "appendFileSync", "readdir", "readdirSync"
      ] and
    node =
      API::moduleImport(["fs", "fs/promises", "node:fs", "node:fs/promises"])
          .getMember(m)
          .getACall()
          .getArgument(0) and
    api = "fs." + m
  )
  or
  cls = "ssrf" and
  (
    node = DataFlow::globalVarRef("fetch").getACall().getArgument(0) and api = "fetch"
    or
    exists(string mod |
      mod = ["node-fetch", "axios", "got", "request", "superagent", "undici"] and
      node = API::moduleImport(mod).getACall().getArgument(0) and
      api = mod
    )
    or
    exists(string mod, string m |
      mod = ["axios", "got"] and
      m = ["get", "post", "put", "delete", "request", "head", "patch"] and
      node = API::moduleImport(mod).getMember(m).getACall().getArgument(0) and
      api = mod + "." + m
    )
    or
    exists(string mod, string m |
      mod = ["http", "https", "node:http", "node:https"] and
      m = ["get", "request"] and
      node = API::moduleImport(mod).getMember(m).getACall().getArgument(0) and
      // strip the node: prefix so the sink api stays colon-free, like child_process/fs above
      api = mod.replaceAll("node:", "") + "." + m
    )
  )
  or
  cls = "sqli" and
  exists(DataFlow::MethodCallNode c, string m |
    m = ["query", "execute", "raw"] and c.getMethodName() = m and node = c.getArgument(0) and
    // Constrain the RECEIVER to a known database client. Matching any `.query()`/
    // `.execute()`/`.raw()` on any object reported a job queue's execute, a URL/query-string
    // builder, or any custom class as HIGH SQL injection. The receiver must flow from one of
    // these packages for the call to be a database sink.
    dbClientReceiver(c.getReceiver()) and
    api = "db." + m
  )
}

module McpTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isMcpSource(source) }

  predicate isSink(DataFlow::Node sink) { dangerousSink(sink, _, _) }
}

module McpTaintFlow = TaintTracking::Global<McpTaintConfig>;

import McpTaintFlow::PathGraph

from McpTaintFlow::PathNode source, McpTaintFlow::PathNode sink, string cls, string api
where McpTaintFlow::flowPath(source, sink) and dangerousSink(sink.getNode(), cls, api)
select sink.getNode(), source, sink,
  "MCP-TAINT[" + cls + "] sink=" + api + ": handler input reaches a " + cls + " sink."
