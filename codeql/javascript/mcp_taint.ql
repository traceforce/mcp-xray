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
    reg.getMethodName() = ["tool", "registerTool", "resource", "setRequestHandler"] and
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
predicate dangerousSink(DataFlow::Node node, string cls, string api) {
  cls = "command_injection" and
  (
    exists(string m |
      m = ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"] and
      node =
        API::moduleImport(["child_process", "node:child_process"]).getMember(m).getACall().getArgument(0) and
      api = "child_process." + m
    )
    or
    node = DataFlow::globalVarRef("eval").getACall().getArgument(0) and api = "eval"
  )
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
      api = mod + "." + m
    )
  )
  or
  cls = "sqli" and
  exists(DataFlow::MethodCallNode c, string m |
    m = ["query", "execute", "raw"] and c.getMethodName() = m and node = c.getArgument(0) and
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
