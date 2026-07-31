/**
 * @name MCP handler input reaches a dangerous sink (Go, interprocedural)
 * @description Deterministic taint detection for Go MCP servers. Sources are the
 *              SDK argument accessors (RequireString/GetArguments/... on the tool
 *              request) that return attacker-controlled input; sinks are a static
 *              per-class list. CodeQL provides the interprocedural, cross-file
 *              dataflow. The matched class is tagged MCP-TAINT[<class>] so the
 *              pipeline recovers it from a single analyze run.
 * @kind path-problem
 * @id mcp/taint-go
 * @problem.severity error
 * @tags security
 */

import go

/**
 * Holds if `c` is a call to an MCP SDK accessor that returns attacker-controlled
 * tool input (mark3labs/mcp-go: request.RequireString/GetString/GetArguments/...;
 * also covers GetArgs/GetRawArguments style accessors).
 *
 * The callee is constrained to the mark3labs/mcp-go SDK package so that unrelated
 * methods elsewhere that merely share these names cannot become false sources.
 */
predicate isMcpSourceCall(DataFlow::CallNode c) {
  c.getTarget().getName() in [
      "RequireString", "GetString", "GetArguments", "RequireInt", "RequireFloat",
      "RequireBool", "GetStringSlice", "GetArgs", "GetRawArguments"
    ] and
  c.getTarget().getPackage().getPath().matches("github.com/mark3labs/mcp-go%")
}

/**
 * Holds if `f` is a tool handler registered with the OFFICIAL SDK
 * (github.com/modelcontextprotocol/go-sdk), i.e. passed to mcp.AddTool / AddPrompt /
 * AddResource as the handler argument.
 *
 * Verified against a real official-SDK fixture rather than inferred from docs: the
 * extractor reports `AddTool` with 3 arguments from package
 * `github.com/modelcontextprotocol/go-sdk/mcp`, whose last argument resolves to the
 * handler FuncDecl.
 */
predicate isOfficialSdkHandler(FuncDef f) {
  exists(DataFlow::CallNode reg, DataFlow::Node h |
    reg.getTarget().getName() in ["AddTool", "AddPrompt", "AddResource", "AddResourceTemplate"] and
    reg.getTarget().getPackage().getPath().matches("github.com/modelcontextprotocol/go-sdk%") and
    h = reg.getAnArgument() and
    f = h.asExpr().(FunctionName).getTarget().getFuncDecl()
  )
}

/**
 * Holds if `source` is the decoded tool-input parameter of an official-SDK handler.
 *
 * The official SDK unmarshals the JSON arguments into a typed struct and hands it to the
 * handler as a parameter -- there is NO accessor call to match, which is why the
 * mark3labs-scoped predicate above finds nothing on such a server and the scan returns a
 * clean-looking zero.
 *
 * The parameter itself is the source; `args.Field` reads propagate by ordinary taint
 * through field reads (probed: `args.Host` is a SelectorExpr whose base is this
 * parameter). The context and request parameters are excluded by TYPE, so the predicate
 * survives signature changes and extra parameters rather than hard-coding index 2.
 */
predicate isOfficialSdkSource(DataFlow::Node source) {
  exists(FuncDef f, Parameter p |
    isOfficialSdkHandler(f) and
    p = f.getParameter(_) and
    not p.getType().getUnderlyingType() instanceof PointerType and
    not p.getType().hasQualifiedName("context", "Context") and
    source = DataFlow::parameterNode(p)
  )
  or
  // The low-level map form: req.Params.Arguments, used when a handler takes the raw
  // request instead of a typed struct.
  exists(DataFlow::FieldReadNode fr |
    fr.getFieldName() = "Arguments" and
    fr.getBase().getType().toString().matches("%Params%") and
    source = fr
  )
}

/**
 * Holds if `node` is a dangerous sink argument for vuln class `cls`, reached via the
 * sink API `api` (the `<pkg>.<func>` the query matched, e.g. `net/http.Get`).
 *
 * Each sink targets only the argument position that carries the dangerous value
 * (the URL, path, or query string), not every argument, to avoid flagging taint
 * into unrelated parameters (content-type, file perms, etc.). command_injection is
 * the deliberate exception: every component of an exec.Command* invocation is part
 * of the executed command line, so a tainted program name OR a tainted argument is
 * RCE (only the leading context.Context of CommandContext is excluded).
 *
 * `api` is emitted in the result message so the pipeline records the precise sink
 * deterministically (from what the query matched) instead of re-deriving it from a
 * source snippet.
 */
predicate dangerousSink(DataFlow::Node node, string cls, string api) {
  cls = "command_injection" and
  (
    exists(DataFlow::CallNode c |
      c.getTarget().hasQualifiedName("os/exec", "Command") and
      node = c.getAnArgument() and
      api = "os/exec.Command"
    )
    or
    // CommandContext(ctx, name, arg...): skip the leading context, every other
    // argument is part of the executed command line.
    exists(DataFlow::CallNode c, int i |
      c.getTarget().hasQualifiedName("os/exec", "CommandContext") and
      i >= 1 and
      node = c.getArgument(i) and
      api = "os/exec.CommandContext"
    )
  )
  or
  cls = "ssrf" and
  exists(DataFlow::CallNode c |
    // net/http.{Get,Post,Head,PostForm}: the URL is always the first argument.
    c.getTarget().hasQualifiedName("net/http", ["Get", "Post", "Head", "PostForm"]) and
    node = c.getArgument(0) and
    api = "net/http." + c.getTarget().getName()
  )
  or
  cls = "path_traversal" and
  exists(DataFlow::CallNode c |
    // os/io-ioutil file APIs: the path/name is always the first argument.
    c.getTarget().hasQualifiedName(["os", "io/ioutil"], ["Open", "ReadFile", "WriteFile", "Create"]) and
    node = c.getArgument(0) and
    api = c.getTarget().getPackage().getPath() + "." + c.getTarget().getName()
  )
  or
  cls = "sqli" and
  exists(DataFlow::CallNode c, Method m | m = c.getTarget() |
    // database/sql DB/Tx/Conn query entrypoints. The query string is arg 0 for the
    // plain variants and arg 1 for the *Context variants (which take ctx first).
    (
      m.hasQualifiedName("database/sql", ["DB", "Tx", "Conn"],
          ["Query", "Exec", "QueryRow", "Prepare"]) and
      node = c.getArgument(0)
      or
      m.hasQualifiedName("database/sql", ["DB", "Tx", "Conn"],
          ["QueryContext", "ExecContext", "QueryRowContext", "PrepareContext"]) and
      node = c.getArgument(1)
    ) and
    api = "database/sql." + m.getName()
  )
}

module McpGoConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode c | isMcpSourceCall(c) and source = c.getResult(0))
    or
    isOfficialSdkSource(source)
  }

  predicate isSink(DataFlow::Node sink) { dangerousSink(sink, _, _) }
}

module McpGoFlow = TaintTracking::Global<McpGoConfig>;

import McpGoFlow::PathGraph

from McpGoFlow::PathNode source, McpGoFlow::PathNode sink, string cls, string api
where McpGoFlow::flowPath(source, sink) and dangerousSink(sink.getNode(), cls, api)
select sink.getNode(), source, sink,
  "MCP-TAINT[" + cls + "] sink=" + api + ": handler input reaches a " + cls + " sink."
