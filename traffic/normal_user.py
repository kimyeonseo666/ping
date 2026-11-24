"""정상 사용자 트래픽 생성기.

고정 IP 컨테이너에서 실행되어 WatchPing! 홈페이지를 평범하게 둘러본다.
탐지 규칙의 기준 아래로 동작하도록 만들어, 공격 트래픽과 구분되는 '정상' 로그를 남기는 것이 목적이다.

- 둘러보는 경로: /, /board?id=N, /search?q=단어, /api/login (고유 경로 4개 → 스캐닝 기준 5개 미만)
- 로그인 실패: 가끔 한 번 틀린 뒤 바로 성공 (브루트포스 기준 1분 5회 미만)

환경 변수
  TARGET_URL     요청 대상 (기본: http://nginx)
  USERNAME       로그인 계정 (기본: member1)
  PASSWORD       로그인 비밀번호 (기본: member1-pw)
  MIN_WAIT/MAX_WAIT  요청 사이 대기 시간(초) (기본: 3 / 10)
  TYPO_RATE      로그인 시 비밀번호를 한 번 틀릴 확률 (기본: 0.2)
"""
import os
import random
import time
import urllib.error
import urllib.parse
import urllib.request

TARGET = os.environ.get("TARGET_URL", "http://nginx").rstrip("/")
USERNAME = os.environ.get("USERNAME", "member1")
PASSWORD = os.environ.get("PASSWORD", "member1-pw")
MIN_WAIT = float(os.environ.get("MIN_WAIT", "3"))
MAX_WAIT = float(os.environ.get("MAX_WAIT", "10"))
TYPO_RATE = float(os.environ.get("TYPO_RATE", "0.2"))

# 일반 브라우저처럼 보이는 User-Agent (정상 사용자 시뮬레이션)
USER_AGENT = os.environ.get(
    "USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
)
SEARCH_WORDS = ["docker", "로그", "회의", "nginx", "발표", "탐지"]
POST_IDS = range(1, 7)


def send(path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(TARGET + path, data=body, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except urllib.error.URLError as e:
        print(f"[{USERNAME}] 연결 실패: {e.reason}", flush=True)
        return None
    method = "POST" if data else "GET"
    print(f"[{USERNAME}] {method} {path} -> {status}", flush=True)
    return status


def login():
    if random.random() < TYPO_RATE:
        send("/api/login", {"username": USERNAME, "password": PASSWORD + "x"})  # 오타 한 번
        time.sleep(random.uniform(2, 4))
    send("/api/login", {"username": USERNAME, "password": PASSWORD})


def browse_once():
    action = random.choices(["home", "post", "search", "login"], weights=[3, 4, 2, 1])[0]
    if action == "home":
        send("/")
    elif action == "post":
        send(f"/board?id={random.choice(POST_IDS)}")
    elif action == "search":
        send("/search?" + urllib.parse.urlencode({"q": random.choice(SEARCH_WORDS)}))
    else:
        login()


def main():
    print(f"[{USERNAME}] 정상 사용자 트래픽 시작 → {TARGET}", flush=True)
    time.sleep(random.uniform(1, 5))  # 여러 사용자가 동시에 시작하지 않도록
    while True:
        browse_once()
        time.sleep(random.uniform(MIN_WAIT, MAX_WAIT))


if __name__ == "__main__":
    main()
