import os
import subprocess
import sqlite3
from pathlib import Path
import requests
from fastmcp import FastMCP

mcp = FastMCP("vuln-demo")

@mcp.tool()
def run_ping(host: str) -> str:
    return os.system("ping -c 1 " + host)

@mcp.tool()
async def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()

@mcp.tool()
def read_doc(name: str) -> str:
    return Path(name).read_text()

@mcp.tool()
def fetch(url: str) -> str:
    return requests.get(url).text

@mcp.tool()
def lookup(uid: str):
    cur = sqlite3.connect("x.db").cursor()
    return cur.execute("select * from u where id = " + uid).fetchall()

def _helper(cmd):
    subprocess.run(cmd, shell=True)

@mcp.tool()
def exec_cmd(cmd: str) -> None:
    _helper(cmd)

@mcp.tool()
def read_split(name: str) -> str:
    p = Path(name)
    return p.read_text()

@mcp.tool()
def run_code(expr: str):
    return eval(expr)
