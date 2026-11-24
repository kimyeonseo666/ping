"""WatchPing! 팀 홈페이지 — 로그 생성용 테스트 웹 애플리케이션.

nginx 뒤에서 동작하며, 로그인 시도 결과를 JSON 인증 로그로 남긴다.
(브루트포스 탐지 등에서 nginx 접속 로그와 함께 활용)

화면 경로는 일부러 적게 유지한다. 탐지 모듈의 스캐닝 규칙이 1분 내 고유 경로 수를 세므로,
정상 사용자가 둘러보기만 해도 오탐이 나지 않도록 게시글 상세는 /board?id= 한 경로로 처리한다.
"""
import json
import os
from datetime import datetime, timezone

from flask import Flask, abort, jsonify, render_template, request

app = Flask(__name__)

AUTH_LOG_PATH = os.environ.get("AUTH_LOG_PATH", "/var/log/app/auth.json.log")
DEMO_USER = os.environ.get("DEMO_USER", "admin")
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "ping-demo-pw")

# 시연용 계정 (실제 서비스 계정 아님). member 계정은 정상 사용자 트래픽 생성기가 사용
USERS = {
    DEMO_USER: DEMO_PASSWORD,
    "member1": "member1-pw",
    "member2": "member2-pw",
    "member3": "member3-pw",
}

TEAM = [
    {"emoji": "📊", "role": "팀장 · 대시보드/시각화", "name": "김연서", "desc": "Kibana 관제 대시보드, 시연 시나리오"},
    {"emoji": "🕵️", "role": "탐지 로직", "name": "김하연", "desc": "스캐닝·브루트포스·인젝션 탐지 규칙, 오탐 튜닝"},
    {"emoji": "🗄️", "role": "저장/파이프라인", "name": "우주연", "desc": "Logstash 전처리, Elasticsearch 인덱스 설계"},
    {"emoji": "🛠️", "role": "수집/인프라", "name": "허유정", "desc": "Nginx·Filebeat 수집, Docker 개발 환경"},
]

POSTS = [
    {"id": 1, "category": "공지", "title": "2학기 프로젝트 킥오프 안내", "date": "2026-09-10",
     "body": "웹로그 수집 분석 & 시각화 프로젝트를 시작합니다. 역할 분담과 일정은 노션을 확인해 주세요."},
    {"id": 2, "category": "공지", "title": "정기 회의 시간 변경 안내", "date": "2026-10-05",
     "body": "이번 주부터 정기 회의는 일요일 오후 9시에 디스코드에서 진행합니다."},
    {"id": 3, "category": "스터디", "title": "Docker Compose로 ELK 스택 띄우기", "date": "2026-10-12",
     "body": "Elasticsearch, Logstash, Kibana, Filebeat를 docker compose up 한 번으로 실행하는 방법을 정리했습니다."},
    {"id": 4, "category": "스터디", "title": "Nginx JSON 접속 로그 포맷 정리", "date": "2026-10-19",
     "body": "log_format 에 escape=json 을 사용해 접속 로그를 JSON 한 줄로 남기는 방법과 필드 목록입니다."},
    {"id": 5, "category": "프로젝트", "title": "공격 탐지 규칙 설계 회의록", "date": "2026-11-02",
     "body": "브루트포스, 스캐닝, SQL 인젝션 탐지 기준과 위험 점수 산정 방식을 논의했습니다."},
    {"id": 6, "category": "프로젝트", "title": "최종 발표 리허설 일정", "date": "2026-11-24",
     "body": "발표 전 리허설은 시연 환경을 초기화한 뒤 시나리오 순서대로 진행합니다."},
]


def find_post(post_id):
    return next((p for p in POSTS if p["id"] == post_id), None)


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


# ---------- 화면 ----------

@app.get("/")
def index():
    return render_template("index.html", team=TEAM, posts=sorted(POSTS, key=lambda p: p["date"], reverse=True))


@app.get("/board")
def board():
    post_id = request.args.get("id", type=int)
    if post_id is None:
        return index()
    post = find_post(post_id)
    if post is None:
        abort(404)
    return render_template("post.html", post=post)


@app.get("/search")
def search():
    q = request.args.get("q", "")
    keyword = q.strip().lower()
    results = [p for p in POSTS
               if keyword and (keyword in p["title"].lower() or keyword in p["body"].lower())]
    return render_template("search.html", q=q, results=results)


@app.errorhandler(404)
def not_found(_):
    return render_template("404.html"), 404


# ---------- API ----------

# 탐지 모듈(python-detector/detectors/bruteforce.py)의 LOGIN_PATH 와 일치해야 함
@app.post("/api/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    success = username in USERS and USERS[username] == password
    write_auth_log(username, success)
    if success:
        return jsonify(result="ok")
    return jsonify(result="invalid credentials"), 401


@app.get("/api/posts/<int:post_id>")
def get_post(post_id):
    post = find_post(post_id)
    if post is None:
        return jsonify(error="not found"), 404
    return jsonify(post)
