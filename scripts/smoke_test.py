"""파이프라인 스모크 테스트 (정상 요청만 전송) — Windows/Mac 공통.

사용법 (저장소 루트에서):
    python scripts/smoke_test.py

표준 라이브러리만 사용하므로 별도 설치 없이 실행된다.
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

BASE = os.environ.get("WEB_HOST", "http://localhost:8080")
ES = os.environ.get("ES_HOST", "http://localhost:9200")
# 인덱스 이름은 저장/파이프라인 설정을 따른다 (예: weblog-raw-YYYY.MM.DD)
INDEX = os.environ.get("SMOKE_INDEX", "weblog-*")
ROOT = Path(__file__).resolve().parent.parent


def request(url, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    with urllib.request.urlopen(url, data=body, timeout=10) as resp:
        return resp.read().decode("utf-8")


def doc_count():
    try:
        return json.loads(request(f"{ES}/{INDEX}/_count"))["count"]
    except Exception:
        return 0


def tail(path, n=1):
    if not path.exists():
        return f"(없음: {path})"
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(lines[-n:])


def main():
    before = doc_count()

    print("[1] 정상 요청 전송")
    request(f"{BASE}/")
    request(f"{BASE}/search?q=hello")
    request(f"{BASE}/api/items/1")
    request(f"{BASE}/login", {"username": "admin", "password": "ping-demo-pw"})
    sent = 4

    print("[2] 최근 로그")
    print(tail(ROOT / "logs" / "nginx" / "access.json.log"))
    print(tail(ROOT / "logs" / "app" / "auth.json.log"))

    print("[3] Elasticsearch 적재 대기 (최대 60초)")
    deadline = time.time() + 60
    after = doc_count()
    while after < before + sent and time.time() < deadline:
        time.sleep(3)
        after = doc_count()

    if after >= before + sent:
        print(f"OK: {INDEX} 문서 {before} -> {after}")
        return 0
    print(f"FAIL: {INDEX} 문서 {before} -> {after} "
          "(docker logs ping-filebeat / ping-logstash 확인)")
    return 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
