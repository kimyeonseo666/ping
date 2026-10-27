# 개발 환경 표준 (v0.1 초안 — 회의에서 확정)

팀 구성: Windows 3명, macOS 1명

## 1. 버전 표

### 각자 PC에 설치하는 것

| 항목 | 버전 | 확인 명령 | 비고 |
|---|---|---|---|
| Python | **3.12.10** | Win: `py -3.12 --version` / Mac: `python3.12 --version` | python.org 공식 설치 파일 사용 (3.12 계열 마지막 설치 파일) |
| Docker Engine | **29.6 이상** | `docker --version` | Docker Desktop 설치 시 함께 설치됨 |
| Docker Compose | **v2 이상** | `docker compose version` | 하이픈 없는 `docker compose` 명령이 동작해야 함 |

### 저장소에 고정된 것 (직접 설치 X, 자동 적용)

| 항목 | 버전 | 고정 위치 |
|---|---|---|
| Elasticsearch / Logstash / Kibana / Filebeat | **8.19.3** | `.env` 의 `ELASTIC_VERSION` (4개는 반드시 같은 버전) |
| nginx | **1.27.5-alpine** | `.env` 의 `NGINX_VERSION` |
| 웹앱 컨테이너 Python | **3.12.10** | `app/Dockerfile` |
| Flask / gunicorn | 3.0.3 / 23.0.0 | `app/requirements.txt` |
| Python 라이브러리 (탐지) | — | `python-detector/requirements.txt` (ES 클라이언트는 서버와 같은 8.x) |
| Node.js | 미정 | 커스텀 프론트엔드 채택 시 결정 |

> 버전을 바꾸고 싶으면 혼자 바꾸지 말고 Discord에 공유 → 이 문서 수정 → 커밋.

## 2. 처음 세팅 순서

### 공통
1. Git, Docker Desktop, Python 3.12 설치
2. **Docker Desktop 메모리 6GB 이상** 할당 (Settings → Resources). ES+Logstash+Kibana가 무거움
3. 저장소 clone — **OneDrive / iCloud 동기화 폴더 밖에** 두기 (로그 파일이 계속 바뀌어 동기화 충돌 발생)

### Windows
```powershell
git config --global core.autocrlf false   # 줄바꿈은 .gitattributes 가 관리
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r python-detector/requirements.txt   # 탐지 스크립트를 실행할 때
```
- `Activate.ps1` 실행이 막히면: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
- Docker Desktop은 WSL2 백엔드 사용

### macOS
```bash
# python.org 에서 3.12.10 macOS installer 설치 (brew는 패치 버전이 달라질 수 있음)
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r python-detector/requirements.txt   # 탐지 스크립트를 실행할 때
```
- Apple Silicon(M1~)도 현재 사용하는 이미지는 모두 ARM 지원

### 실행 확인 (공통)
```
cp .env.example .env             # 처음 한 번만 (Windows PowerShell: copy .env.example .env)
docker compose up -d
python scripts/smoke_test.py     # "OK: ..." 가 나오면 성공
```
- `port is already allocated` 오류가 나면 다른 프로그램이 8080을 쓰는 중이다. `.env` 의 `NGINX_HTTP_PORT` 를 8081 등으로 바꾸고,
  스모크 테스트는 `WEB_HOST=http://localhost:8081 python scripts/smoke_test.py` 로 실행한다.

## 3. 규칙
- 파일 인코딩 UTF-8, 줄바꿈 LF (`.editorconfig`, `.gitattributes` 로 자동 적용)
- 스크립트는 **Python으로 작성** (PowerShell/bash 전용 스크립트는 한쪽 OS에서 안 돌아감)
- 파일 경로는 코드에 하드코딩하지 말고 `pathlib` 사용
- `.venv/`, `logs/`, `.env` 는 커밋하지 않음
