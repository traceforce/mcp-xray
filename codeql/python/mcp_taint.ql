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
predicate dangerousSink(DataFlow::Node node, string cls) {
  cls = "ssrf" and
  (
    exists(string m | m in ["get", "post", "put", "delete", "head", "patch"] |
      node = API::moduleImport("requests").getMember(m).getACall().getArg(0)
    )
    or
    node = API::moduleImport("urllib").getMember("request").getMember("urlopen").getACall().getArg(0)
    or
    exists(string m | m in ["get", "post"] |
      node = API::moduleImport("httpx").getMember(m).getACall().getArg(0)
    )
    or
    // requests.request/httpx.request(method, url, ...): the URL is the 2nd positional
    // argument (or the `url=` keyword), not arg 0, which is the HTTP method.
    exists(API::CallNode c | c = API::moduleImport(["requests", "httpx"]).getMember("request").getACall() |
      node = c.getArg(1) or node = c.getArgByName("url")
    )
  )
  or
  cls = "command_injection" and
  (
    node = API::moduleImport("os").getMember(["system", "popen"]).getACall().getArg(0)
    or
    node =
      API::moduleImport("subprocess")
          .getMember(["run", "call", "Popen", "check_output", "check_call"])
          .getACall()
          .getArg(0)
  )
  or
  // eval/exec run attacker input as code -- code injection (INJECTION-CODE), a distinct
  // class from shell command injection, matching the opengrep taxonomy so both engines
  // agree on Python (the one language they both cover).
  cls = "code_injection" and
  node = API::builtin(["eval", "exec"]).getACall().getArg(0)
  or
  cls = "path_traversal" and
  (
    node = API::builtin("open").getACall().getArg(0)
    or
    // os.open is a read/write open (not just delete); grouped with the delete-family sinks.
    node = API::moduleImport("os").getMember(["remove", "unlink", "mkdir", "rmdir", "open"]).getACall().getArg(0)
    or
    // io.open / codecs.open -- the same file-open sink under different modules.
    node = API::moduleImport("io").getMember("open").getACall().getArg(0)
    or
    node = API::moduleImport("codecs").getMember("open").getACall().getArg(0)
    or
    // pathlib.Path(tainted) -- the tainted path enters at construction; a later .read_text()/
    // .write_text()/.open() on it is the read. This is the most common Python file-read shape and
    // was previously found by NEITHER engine on a cross-file flow (OpenGrep is intra-file only).
    node = API::moduleImport("pathlib").getMember("Path").getACall().getArg(0)
    or
    // shutil copy/move (first arg is the source path an attacker can point out of bounds).
    node =
      API::moduleImport("shutil")
          .getMember(["copy", "copyfile", "copy2", "copytree", "move"])
          .getACall()
          .getArg(0)
    or
    // archive open (tarfile/zipfile) -- the archive path itself is a traversal-controllable read.
    node = API::moduleImport("tarfile").getMember("open").getACall().getArg(0)
    or
    node = API::moduleImport("zipfile").getMember("ZipFile").getACall().getArg(0)
  )
  or
  cls = "sqli" and
  exists(DataFlow::CallCfgNode c |
    c.getFunction().(DataFlow::AttrRead).getAttributeName() in
      ["execute", "executescript", "executemany"] and
    node = c.getArg(0)
  )
}

module McpTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Function f |
      isMcpHandler(f) and
      source.(DataFlow::ParameterNode).getParameter() = f.getArg(_)
    )
  }

  predicate isSink(DataFlow::Node sink) { dangerousSink(sink, _) }
}

module McpTaintFlow = TaintTracking::Global<McpTaintConfig>;

import McpTaintFlow::PathGraph

from McpTaintFlow::PathNode source, McpTaintFlow::PathNode sink, string cls
where McpTaintFlow::flowPath(source, sink) and dangerousSink(sink.getNode(), cls)
select sink.getNode(), source, sink,
  "MCP-TAINT[" + cls + "]: handler input reaches a " + cls + " sink."
