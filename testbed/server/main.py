"""
A simple FastAPI application that serves a single endpoint
to test active TCP connections.
"""

from typing import List
from fastapi import FastAPI, HTTPException
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

@app.get("/connections", response_model=List[TCPConnectionInformation])
def list_tcp_connections() -> List[TCPConnectionInformation]:
    """
    An endpoint to manage and enumerate TCP connections toward the server.
    """
    try:
        connections = psutil.net_connections(kind="tcp")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving connections: {e}")

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

    return results

