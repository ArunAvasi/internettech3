#!/usr/bin/env python3
"""
server.py — project 3, Steps 1‑6 only (adds cookie-based auth)

A minimal HTTP/1.1 server that:
  1. Serves a login form (GET /)
  2. Accepts POSTed username & password
  3. Validates against passwords.txt
  4. On success, shows the user's secret from secrets.txt
  5. On failure, shows a Bad credentials page
  6. Remembers authenticated users via cookies
"""

import socket
import signal
import sys
import urllib.parse
import random

# -------------------------------------------------------------------------
# 0 Command-line / startup
# -------------------------------------------------------------------------
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

# -------------------------------------------------------------------------
# 1 Load user databases
# -------------------------------------------------------------------------
credentials = {}
with open("passwords.txt") as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 2:
            user, pwd = parts[0], parts[1]
            credentials[user] = pwd

secrets = {}
with open("secrets.txt") as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 2:
            user, secret = parts[0], parts[1]
            secrets[user] = secret

# -------------------------------------------------------------------------
# 2 Static HTML fragments
# -------------------------------------------------------------------------
LOGIN_FORM = """
<form action="/" method="post">
  Name: <input type="text" name="username"><br/>
  Password: <input type="text" name="password"><br/>
  <input type="submit" value="Submit">
</form>
"""
LOGIN_PAGE       = "<h1>Please login</h1>" + LOGIN_FORM
BAD_CREDS_PAGE   = "<h1>Bad credentials</h1>" + LOGIN_FORM
SUCCESS_PAGE_HEAD = "<h1>Welcome!</h1><h2>Your secret data is here:</h2>"

# -------------------------------------------------------------------------
# 3 Signal handler for clean shutdown
# -------------------------------------------------------------------------
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("", PORT))
sock.listen(5)

def shutdown(sig, frame):
    print("\nShutting down…")
    sock.close()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)

# -------------------------------------------------------------------------
# 4 HTTP parsing & response helpers
# -------------------------------------------------------------------------

def parse_request(client):
    # Read until end of headers
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = client.recv(1024)
        if not chunk:
            break
        data += chunk

    header_part, _, rest = data.partition(b"\r\n\r\n")
    header_text = header_part.decode("iso-8859-1")
    lines = header_text.split("\r\n")
    request_line = lines[0].split(" ", 2)
    if len(request_line) != 3:
        return None, None, {}, ""
    method, path, _ = request_line

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    body = b""
    if method.upper() == "POST":
        length = int(headers.get("Content-Length", "0"))
        body = rest
        while len(body) < length:
            chunk = client.recv(1024)
            if not chunk:
                break
            body += chunk
        body = body[:length]

    return method.upper(), path, headers, body.decode("utf-8", errors="replace")


def send_response(client, status, body_html, extra_headers=None):
    # Build and send HTTP/1.1 response with optional extra headers
    body_bytes = body_html.encode("utf-8")
    resp_lines = [f"HTTP/1.1 {status}"]
    if extra_headers:
        for h in extra_headers:
            resp_lines.append(h)
    resp_lines.extend([
        "Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body_bytes)}",
        "Connection: close",
        "",
        ""
    ])
    header_bytes = "\r\n".join(resp_lines).encode("utf-8")
    client.sendall(header_bytes + body_bytes)
    client.close()

# -------------------------------------------------------------------------
# 5 Cookie store
# -------------------------------------------------------------------------
# Maps token string → username
sessions = {}

# -------------------------------------------------------------------------
# 6 Main server loop (with cookie logic)
# -------------------------------------------------------------------------
print(f"Listening on port {PORT}… (Steps 1–6 only)")

while True:
    client, addr = sock.accept()
    method, path, headers, body = parse_request(client)

    # Only support the root path
    if path != "/":
        send_response(client, "404 Not Found", "<h1>404 Not Found</h1>")
        continue

    # Extract 'token' from Cookie header, if present
    cookie_header = headers.get("Cookie", "")
    token = None
    if cookie_header:
        for kv in cookie_header.split(";"):
            k, sep, v = kv.strip().partition("=")
            if k == "token" and sep:
                token = v
                break

    # ----- Case C/D: cookie-based authentication -----
    if token is not None:
        if token in sessions:
            # Case C: valid cookie → welcome
            user = sessions[token]
            secret = secrets.get(user, "(no secret found)")
            body_html = SUCCESS_PAGE_HEAD + f"<p>{secret}</p>"
            send_response(client, "200 OK", body_html)
        else:
            # Case D: invalid cookie → bad credentials
            send_response(client, "200 OK", BAD_CREDS_PAGE)
        continue

    # ----- No cookie present: fall back to username/password -----
    if method != "POST":
        # Basic case: show login form
        send_response(client, "200 OK", LOGIN_PAGE)
        continue

    # Parse form-encoded POST body
    fields = {}
    for pair in body.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            fields[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)

    username = fields.get("username", "").strip()
    password = fields.get("password", "").strip()

    # ----- Case A: valid POST credentials -----
    if username and password and credentials.get(username) == password:
        # Generate and store a new cookie
        new_token = str(random.getrandbits(64))
        sessions[new_token] = username
        extra = [f"Set-Cookie: token={new_token}"]

        secret = secrets.get(username, "(no secret found)")
        body_html = SUCCESS_PAGE_HEAD + f"<p>{secret}</p>"
        send_response(client, "200 OK", body_html, extra)
        continue

    # ----- Case B: POST with missing or bad credentials -----
    # (includes exactly one field missing or invalid combo)
    if username or password:
        send_response(client, "200 OK", BAD_CREDS_PAGE)
    else:
        # blank POST → show login page
        send_response(client, "200 OK", LOGIN_PAGE)
