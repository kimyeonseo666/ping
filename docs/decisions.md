# 결정 기록

회의에서 확정된 내용만 기록한다. 바뀌면 줄을 지우지 말고 "변경" 항목을 추가한다.

## 2026-09-26 회의 (수집/인프라 결정 제안서)

### 확정
| # | 항목 | 결정 | 반영 위치 |
|---|---|---|---|
| 1 | 실행 환경 | 로컬 Docker Compose | `docker-compose.yml` |
| 2·7 | 수집 경로 | Nginx → Filebeat → **Logstash** → Elasticsearch (ES 직결 X) | `filebeat/filebeat.yml`, `logstash/pipeline/` |

### 미확정 (다음 회의 안건)
| # | 항목 | 제안안 | 주도 | 비고 |
|---|---|---|---|---|
| 3 | 공격 대상 웹앱 | Flask 직접 제작 (로그인·검색·다운로드) | 허유정 ↔ 김하연 | 엔드포인트 범위·기한 정해야 함. 현재 로그인·검색만 구현 |
| 4 | IP 구분 | compose 네트워크 고정 IP 컨테이너 (공격자 172.20.0.10, 정상 172.20.0.20~29) | 허유정 ↔ 김하연 | 현재 모든 요청이 게이트웨이 IP(172.18.0.1)로 기록됨 |
| 5 | 접속 로그 필드 | 10개 필드 (timestamp, remote_addr, method, uri, status, bytes, request_time, referer, user_agent, request_id) | 허유정 ↔ 김하연 | 현재 구현은 필드명이 다름 → 확정 시 변경 |
| 6 | 로그인 실패 기준 | 401 응답을 1차 기준 | 김하연 | 앱 인증 로그 필드명(src_ip vs remote_addr)도 함께 결정 |
| 8 | ES/Kibana 버전·메모리 | 팀원 PC RAM 조사 후 확정 | 우주연 | 현재 8.19.3, ES 힙 1GB로 동작 확인 |
| — | URL 디코딩 위치 | 저장 단계(Logstash)에서 디코딩 필드 추가 | 우주연 | 디코딩 필드명 `decoded_uri`, 인덱스 `weblog-raw-YYYY.MM.DD` (우주연 설계) |

## 2026-10-27 GitHub 협업 규칙

### 확정
| 항목 | 결정 |
|---|---|
| 브랜치 흐름 | 작업 브랜치 → **dev** 로 PR. **main** 에는 시연 가능한 버전만 dev → main 으로 병합 |
| 이슈·PR 템플릿 | `.github/` 에 두어 자동 적용 (PR #2) |
| 커밋·PR·이슈 말머리 | Conventional Commits: `feat:` `fix:` `docs:` `chore:` `refactor:` `test:` |
