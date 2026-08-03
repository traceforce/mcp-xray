"""Label-parity fixture: one tool per sink family that BOTH engines cover.

Every handler here must be reported by OpenGrep and CodeQL with the SAME SinkAPI string.
SinkAPI is part of sinkIdentity (the cross-engine merge key), so a mismatch silently splits
one vulnerability into two reports -- worse than unknown_sink, because it looks correct.

Calls are deliberately written across MULTIPLE LINES: that is the shape that used to defeat
the adapter's snippet recovery and produce unknown_sink for the CodeQL side.
"""
import asyncio
import codecs
import io
import os
import shutil
import subprocess
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("parity")


@mcp.tool()
def t_os_system(cmd: str) -> str:
    """tool."""
    return str(os.system(
        cmd,
    ))


@mcp.tool()
def t_os_popen(cmd: str) -> str:
    """tool."""
    return os.popen(
        cmd,
    ).read()


@mcp.tool()
def t_subprocess_run_shell(cmd: str) -> str:
    """tool."""
    return str(subprocess.run(
        cmd,
        shell=True,
    ))


@mcp.tool()
def t_subprocess_popen_shell(cmd: str) -> str:
    """tool."""
    return str(subprocess.Popen(
        cmd,
        shell=True,
    ))


@mcp.tool()
def t_getoutput(cmd: str) -> str:
    """tool."""
    return subprocess.getoutput(
        cmd,
    )


@mcp.tool()
async def t_create_subprocess_shell(cmd: str) -> str:
    """tool."""
    p = await asyncio.create_subprocess_shell(
        cmd,
    )
    return str(p.pid)


@mcp.tool()
def t_open(path: str) -> str:
    """tool."""
    with open(
        path,
    ) as f:
        return f.read()


@mcp.tool()
def t_io_open(path: str) -> str:
    """tool."""
    with io.open(
        path,
    ) as f:
        return f.read()


@mcp.tool()
def t_codecs_open(path: str) -> str:
    """tool."""
    with codecs.open(
        path,
    ) as f:
        return f.read()


@mcp.tool()
def t_os_open(path: str) -> str:
    """tool."""
    return str(os.open(
        path,
        os.O_RDONLY,
    ))


@mcp.tool()
def t_pathlib_read(name: str) -> str:
    """tool."""
    # Inline Path(x).read_text(): CodeQL reports the Path() node, OpenGrep the read, both on
    # THIS single line. They must agree on pathlib.Path or sinkIdentity (line + api) splits
    # the finding into two -- the V43-4 regression, which had no pathlib case here to catch.
    return Path(name).read_text()


@mcp.tool()
def t_open_with_path(name: str) -> str:
    """tool."""
    # The other half of the same trap, and the one that was missing: the sink here is open(),
    # and Path() only builds its argument. A label rule that claims any line mentioning
    # `Path(` for pathlib reports this as pathlib.Path while CodeQL reports open -- the same
    # split, in the shape people actually write when joining a base dir to a user path.
    with open(Path("/srv/data") / name) as f:
        return f.read()


@mcp.tool()
def t_shutil_move(src: str) -> str:
    """tool."""
    return str(shutil.move(
        src,
        "/tmp/dest",
    ))


@mcp.tool()
def t_requests_get(url: str) -> str:
    """tool."""
    return requests.get(
        url,
    ).text


@mcp.tool()
def t_requests_post(url: str) -> str:
    """tool."""
    return requests.post(
        url,
    ).text


@mcp.tool()
def t_eval(expr: str) -> str:
    """tool."""
    return str(eval(
        expr,
    ))


@mcp.tool()
def t_sqli(q: str, cur=None) -> str:
    """tool."""
    return str(cur.execute(
        q,
    ))
