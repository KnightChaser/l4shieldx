"""
A simple FastAPI application that serves a single endpoint
to test active TCP connections, with HTML output and root redirection.
"""

from typing import List
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
import psutil

app = FastAPI(title="TCP Connection Inspector")

class TCPConnectionInformation(BaseModel):
    pid: int | None
    laddr: str
    lport: int
    raddr: str | None
    rport: int | None
    status: str

@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    """
    Redirect root URL to /connections
    """
    return RedirectResponse(url="/connections")

@app.get("/connections", response_class=HTMLResponse)
def list_tcp_connections(request: Request) -> HTMLResponse:
    """
    An endpoint to enumerate active TCP connections toward this server.
    Outputs an HTML table and a brief summary.
    """
    try:
        connections = psutil.net_connections(kind="tcp")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving connections: {e}")

    # Filter connections toward this server port
    server_port = request.url.port or request.scope.get("server", [None, None])[1]
    if server_port is not None:
        connections = [c for c in connections if c.laddr and c.laddr[1] == server_port]

    results: List[TCPConnectionInformation] = []
    for conn in connections:
        # local address (always present)
        if conn.laddr:
            laddr, lport = conn.laddr
        else:
            laddr, lport = "", 0

        # remote address may be empty
        if conn.raddr:
            raddr, rport = conn.raddr
        else:
            raddr, rport = None, None

        results.append(TCPConnectionInformation(
            pid=conn.pid,
            laddr=laddr,
            lport=lport,
            raddr=raddr,
            rport=rport,
            status=conn.status
        ))

    # Build HTML output
    total = len(results)
    html = [
        "<html>",
        "<head><title>TCP Connections</title></head>",
        "<body>",
        f"<h2>Total TCP connections: {total}</h2>",
        "<table border='1' cellpadding='5' cellspacing='0'>",
        "<tr><th>PID</th><th>Local Address</th><th>Local Port</th>"
        "<th>Remote Address</th><th>Remote Port</th><th>Status</th></tr>"
    ]
    for info in results:
        html.append(
            "<tr>"
            f"<td>{info.pid if info.pid is not None else '-'}</td>"
            f"<td>{info.laddr}</td>"
            f"<td>{info.lport}</td>"
            f"<td>{info.raddr if info.raddr else '-'}</td>"
            f"<td>{info.rport if info.rport is not None else '-'}</td>"
            f"<td>{info.status}</td>"
            "</tr>"
        )
    html.extend(["</table>", "</body>", "</html>"])

    return HTMLResponse(content="\n".join(html), status_code=200)

