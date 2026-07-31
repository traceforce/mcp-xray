/**
 * @name MCP handler input reaches a dangerous sink (interprocedural)
 * @description Deterministic taint detection for MCP servers. Sources are the
 *              parameters of structurally-detected MCP tool/resource handlers
 *              (decorator-based registration); sinks are a static per-class list.
 *              CodeQL provides the interprocedural, cross-file dataflow. One query;
 *              the matched vuln class is tagged in the message as MCP-TAINT[<class>]
 *              so the pipeline can recover it from a single analyze run.
 * @kind path-problem
 * @id mcp/taint
 * @problem.severity error
 * @tags security
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

/**
 * Holds if `d` is a decorator expression that registers an MCP tool/resource
 * handler, e.g. `@mcp.tool()`, `@app.tool`, `@server.resource(...)`,
 * `@server.call_tool()`. Matches both the call form and the bare-attribute form.
 */
predicate isMcpHandlerDecorator(Expr d) {
  exists(Attribute a |
    (a = d or a = d.(Call).getFunc()) and
    a.getName() in ["tool", "resource", "call_tool"]
  )
}

/** Holds if `f` is registered as an MCP handler (carries an MCP handler decorator). */
predicate isMcpHandler(Function f) { isMcpHandlerDecorator(f.getADecorator()) }

/**
 * Holds if `node` is a dangerous sink argument for vuln class `cls`. Static,
 * deterministic per-class lists; CodeQL still requires taint to actually reach
 * them, so a broad list does not create false positives without a real flow.
 */
/**
 * Holds if `node` is a dangerous sink argument for class `cls`, reached via sink API `api`.
 *
 * `api` is emitted into the SARIF message as `sink=<api>` so the adapter reads it
 * deterministically from the query instead of re-deriving it from source text. The Python
 * pack previously omitted it (js/go both emit), which forced snippet recovery and yielded
 * `unknown_sink` on calls wrapped across lines.
 *
 * CRITICAL: these strings must match `canonicalSinkAPI` in parse.go EXACTLY, because
 * SinkAPI is part of `sinkIdentity` (the cross-engine merge key). A subtly-wrong label is
 * WORSE than unknown_sink -- it looks correct while silently splitting one vulnerability
 * into two reports. TestSinkAPILabelParity pins every label pair.
 */
predicate dangerousSink(DataFlow::Node node, string cls, string api) {
  cls = "ssrf" and
  (
    // canonicalSinkAPI keeps requests.get/post distinct but folds put/delete/head/patch
    // (and their httpx twins) into http.<verb>; mirror that split exactly.
    exists(string m | m in ["get", "post"] |
      node = API::moduleImport("requests").getMember(m).getACall().getArg(0) and
      api = "requests." + m
    )
    or
    exists(string m | m in ["put", "delete", "head", "patch"] |
      node = API::moduleImport("requests").getMember(m).getACall().getArg(0) and
      api = "http." + m
    )
    or
    node = API::moduleImport("urllib").getMember("request").getMember("urlopen").getACall().getArg(0) and
    api = "urllib.urlopen"
    or
    exists(string m | m in ["get", "post"] |
      node = API::moduleImport("httpx").getMember(m).getACall().getArg(0) and
      api = "httpx." + m
    )
    or
    exists(string m | m in ["put", "delete", "head", "patch"] |
      node = API::moduleImport("httpx").getMember(m).getACall().getArg(0) and
      api = "http." + m
    )
    or
    // requests.request/httpx.request(method, url, ...): the URL is the 2nd positional
    // argument (or the `url=` keyword), not arg 0, which is the HTTP method.
    exists(API::CallNode c | c = API::moduleImport("requests").getMember("request").getACall() |
      (node = c.getArg(1) or node = c.getArgByName("url")) and api = "requests.request"
    )
    or
    // httpx.request has no dedicated canonicalSinkAPI arm; it lands on the generic
    // `.request(` arm, which labels http.request. Match that, do not invent httpx.request.
    exists(API::CallNode c | c = API::moduleImport("httpx").getMember("request").getACall() |
      (node = c.getArg(1) or node = c.getArgByName("url")) and api = "http.request"
    )
  )
  or
  cls = "command_injection" and
  (
    exists(string m | m in ["system", "popen"] |
      node = API::moduleImport("os").getMember(m).getACall().getArg(0) and api = "os." + m
    )
    or
    // Shelled subprocess. canonicalSinkAPI appends the +shell=True suffix; without it the
    // two engines produce different labels for the same call and stop merging.
    exists(API::CallNode c, string m |
      m in ["run", "call", "Popen", "check_output", "check_call"] and
      c = API::moduleImport("subprocess").getMember(m).getACall() and
      c.getArgByName("shell").asExpr().(BooleanLiteral).booleanValue() = true and
      node = c.getArg(0) and
      api = "subprocess." + m + "+shell=True"
    )
    or
    exists(string m | m in ["getoutput", "getstatusoutput"] |
      node = API::moduleImport("subprocess").getMember(m).getACall().getArg(0) and
      api = "subprocess." + m
    )
    or
    node = API::moduleImport("asyncio").getMember("create_subprocess_shell").getACall().getArg(0) and
    api = "asyncio.create_subprocess_shell"
    or
    exists(string m |
      m in [
          "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe",
          "spawnl", "spawnle", "spawnlp", "spawnv", "spawnve", "spawnvp", "spawnvpe"
        ] and
      node = API::moduleImport("os").getMember(m).getACall().getArg(0) and
      api = "os." + m
    )
  )
  or
  cls = "code_injection" and
  exists(string m | m in ["eval", "exec"] |
    node = API::builtin(m).getACall().getArg(0) and api = m
  )
  or
  cls = "path_traversal" and
  (
    node = API::builtin("open").getACall().getArg(0) and api = "open"
    or
    // canonicalSinkAPI folds unlink into os.remove and makedirs into os.mkdir.
    exists(string m | m in ["remove", "unlink"] |
      node = API::moduleImport("os").getMember(m).getACall().getArg(0) and api = "os.remove"
    )
    or
    exists(string m | m in ["mkdir", "makedirs"] |
      node = API::moduleImport("os").getMember(m).getACall().getArg(0) and api = "os.mkdir"
    )
    or
    node = API::moduleImport("os").getMember("rmdir").getACall().getArg(0) and api = "os.rmdir"
    or
    node = API::moduleImport("os").getMember("open").getACall().getArg(0) and api = "os.open"
    or
    node = API::moduleImport("io").getMember("open").getACall().getArg(0) and api = "io.open"
    or
    node = API::moduleImport("codecs").getMember("open").getACall().getArg(0) and api = "codecs.open"
    or
    node = API::moduleImport("pathlib").getMember("Path").getACall().getArg(0) and
    api = "pathlib.Path"
    or
    exists(string m | m in ["copy", "copyfile", "copy2", "copytree", "move"] |
      node = API::moduleImport("shutil").getMember(m).getACall().getArg(0) and
      api = "shutil." + m
    )
    or
    node = API::moduleImport("tarfile").getMember("open").getACall().getArg(0) and
    api = "tarfile.open"
    or
    node = API::moduleImport("zipfile").getMember("ZipFile").getACall().getArg(0) and
    api = "zipfile.ZipFile"
  )
  or
  cls = "sqli" and
  exists(DataFlow::CallCfgNode c, string m |
    m = c.getFunction().(DataFlow::AttrRead).getAttributeName() and
    m in ["execute", "executescript", "executemany"] and
    node = c.getArg(0) and
    // canonicalSinkAPI labels these executescript / cursor.executemany / cursor.execute.
    (
      m = "executescript" and api = "executescript"
      or
      m = "executemany" and api = "cursor.executemany"
      or
      m = "execute" and api = "cursor.execute"
    )
  )
}

module McpTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Function f |
      isMcpHandler(f) and
      source.(DataFlow::ParameterNode).getParameter() = f.getArg(_)
    )
  }

  predicate isSink(DataFlow::Node sink) { dangerousSink(sink, _, _) }
}

module McpTaintFlow = TaintTracking::Global<McpTaintConfig>;

import McpTaintFlow::PathGraph

from McpTaintFlow::PathNode source, McpTaintFlow::PathNode sink, string cls, string api
where McpTaintFlow::flowPath(source, sink) and dangerousSink(sink.getNode(), cls, api)
select sink.getNode(), source, sink,
  "MCP-TAINT[" + cls + "] sink=" + api + ": handler input reaches a " + cls + " sink."
