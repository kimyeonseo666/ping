# 로그 포맷 설계서 (v0.1 초안)

담당: 허유정 (수집/인프라) · 탐지 담당(김하연), 저장 담당(우주연)과 필드 합의 필요

> 이 문서는 **수집 단계(nginx·앱이 남기는 로그 파일)** 의 필드를 정의한다.
> 저장 인덱스 이름(`weblog-raw-YYYY.MM.DD`), 매핑, 디코딩 필드(`decoded_uri`)는 저장/파이프라인 담당(우주연)이 `logstash/`, `elasticsearch/` 에서 정의한다.
> Filebeat는 JSON을 필드로 분리하고 `log_type`(`nginx` / `auth`)을 붙여 `logstash:5044` 로 보낸다.

## 1. nginx 접속 로그 — `logs/nginx/access.json.log`

| 필드 | 타입(ES) | 예시 | 설명 / 탐지 활용 |
|---|---|---|---|
| `@timestamp` | date | 2026-09-26T05:02:31Z | `time`을 파싱한 이벤트 시각 |
| `time` | keyword | 2026-09-26T14:02:31+09:00 | nginx 원본 시각 |
| `request_id` | keyword | 3f2a... | 요청 고유 ID (웹앱 인증 로그와 연결용) |
| `remote_addr` | ip | 203.0.113.5 | 출발지 IP — 모든 탐지의 집계 기준 |
| `x_forwarded_for` | keyword | | 프록시/LB 뒤 원 IP (EC2+ALB 구성 시 중요) |
| `host` | keyword | localhost | |
| `request_method` | keyword | GET | |
| `request_uri` | keyword | /search?q=... | 원본(인코딩된) 경로+쿼리 |
| `uri` | keyword | /search | 쿼리 제외 경로 — 스캐닝(다수 404 경로) 집계 |
| `args` | keyword | q=hello | 쿼리 스트링 |
| `server_protocol` | keyword | HTTP/1.1 | |
| `status` | integer | 404 | 401 급증 → 브루트포스, 404 급증 → 스캐닝 |
| `body_bytes_sent` | integer | 512 | |
| `request_length` | integer | 380 | |
| `request_time` | float | 0.004 | 응답 지연 — DDoS 징후 |
| `upstream_status` | integer | 200 | |
| `upstream_response_time` | float | 0.003 | |
| `http_referer` | keyword | | |
| `http_user_agent` | keyword | curl/8.x | 자동화 도구 UA 식별 |
| `log_type` | keyword | nginx | Filebeat에서 부여 |

## 2. 웹앱 인증 로그 — `logs/app/auth.json.log`

| 필드 | 타입 | 설명 |
|---|---|---|
| `time` / `@timestamp` | date | 이벤트 시각 (UTC) |
| `request_id` | keyword | nginx 로그와 조인용 |
| `remote_addr` | ip | 클라이언트 IP (nginx가 전달한 X-Real-IP) |
| `event` | keyword | `login` |
| `username` | keyword | 시도한 계정명 |
| `result` | keyword | `success` / `failure` |
| `http_user_agent` | keyword | |
| `log_type` | keyword | auth |

## 3. 미결 사항 (팀 회의 안건)
- [ ] 필드명 최종 확정 (김하연) — 결정 제안서의 10개 필드안과 맞춰 변경 예정
- [ ] 인덱스 템플릿/매핑 확정 (우주연)
- [ ] JSON 파싱 위치 합의 (우주연) — 현재 Filebeat에서 파싱
- [ ] POST body 로깅 여부 — 로그인 비밀번호 등 민감정보가 섞이므로 기본은 **미수집**
- [ ] 타임존 통일 (nginx는 KST 오프셋 포함, 웹앱은 UTC → `@timestamp`는 모두 UTC로 저장됨)
- [ ] Apache도 지원할지 여부 (지원 시 동일 필드명으로 맞추는 LogFormat 작성)
