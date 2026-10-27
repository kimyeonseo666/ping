"""로그 생성용 테스트 웹 애플리케이션.

nginx 뒤에서 동작하며, 로그인 시도 결과를 JSON 인증 로그로 남긴다.
(브루트포스 탐지 등에서 nginx 접속 로그와 함께 활용)
"""
import json
import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from markupsafe import escape

app = Flask(__name__)

AUTH_LOG_PATH = os.environ.get("AUTH_LOG_PATH", "/var/log/app/auth.json.log")
DEMO_USER = os.environ.get("DEMO_USER", "admin")
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "ping-demo-pw")


def client_ip():
    return request.headers.get("X-Real-IP", request.remote_addr)


def write_auth_log(username, success):
    record = {
        "time": datetime.now(timezone.utc).isoformat(),
        "request_id": request.headers.get("X-Request-ID", ""),
        "remote_addr": client_ip(),
        "event": "login",
        "username": username,
        "result": "success" if success else "failure",
        "http_user_agent": request.headers.get("User-Agent", ""),
    }
    os.makedirs(os.path.dirname(AUTH_LOG_PATH), exist_ok=True)
    with open(AUTH_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


@app.get("/")
def index():
    return "<h1>Ping! test web app</h1>"


@app.get("/search")
def search():
    q = request.args.get("q", "")
    return f"<p>검색어: {escape(q)}</p>"


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    success = username == DEMO_USER and password == DEMO_PASSWORD
    write_auth_log(username, success)
    if success:
        return jsonify(result="ok")
    return jsonify(result="invalid credentials"), 401


@app.get("/api/items/<int:item_id>")
def get_item(item_id):
    return jsonify(id=item_id, name=f"item-{item_id}")
