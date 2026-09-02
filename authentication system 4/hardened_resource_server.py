"""
vulnerable/resource_server.py   (port 5002)
===========================================
A minimal OAuth 2.0 resource server. It protects /api/profile behind a
bearer access token, which it validates by looking the opaque token up in
the AS token store (shared SQLite file -- stands in for token introspection).

The RS itself is not the focus of System 4's attacks; it exists so that a
stolen access token has somewhere meaningful to be spent, demonstrating
real impact (attacks 1 and 3).
"""
import os
import sqlite3
from flask import Flask, request, jsonify

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oauth_hard.db")
app = Flask(__name__)


def lookup(token):
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    row = c.execute("SELECT * FROM tokens WHERE token=?", (token,)).fetchone()
    c.close()
    return row


@app.route("/api/profile")
def profile():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify(error="missing token"), 401
    row = lookup(auth.split(" ", 1)[1])
    if not row:
        return jsonify(error="invalid token"), 401
    # the protected resource: the victim's account data
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    user = c.execute("SELECT username,email FROM users WHERE username=?",
                     (row["username"],)).fetchone()
    c.close()
    return jsonify(username=user["username"], email=user["email"],
                   scope=row["scope"], note="SENSITIVE ACCOUNT DATA")


if __name__ == "__main__":
    print("[hard-rs] listening on :5002")
    app.run(port=5002, threaded=True)
