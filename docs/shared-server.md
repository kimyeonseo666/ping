# 팀 공용 서버 (Tailscale)

AWS 없이 팀원 PC 한 대를 공용 서버로 쓰고, 나머지 팀원은 Tailscale로 접속한다.

```
호스트 PC (Docker, compose 1벌) ◀── Tailscale ──┬── 팀원 A
                                               ├── 팀원 B
                                               └── 팀원 C
```

- **개발은 각자 로컬**에서 한다. 공용 서버는 통합 확인, 시연 리허설용이다.
- 호스트 PC가 꺼지거나 절전 모드에 들어가면 접속이 끊긴다.

## 1. 호스트 PC 세팅 (1회)

1. Tailscale 설치: https://tailscale.com/download → 로그인
2. 호스트의 Tailscale 주소 확인
   ```
   tailscale ip -4
   ```
   `100.x.x.x` 형태의 주소가 나온다.
3. `.env` 에 주소 입력 (`.env` 가 없으면 먼저 `cp .env.example .env`)
   ```
   TAILSCALE_IP=100.x.x.x
   ```
4. **팀원에게 호스트 PC 공유하기** (Tailscale 관리 화면)
   - https://login.tailscale.com/admin/machines → 호스트 PC 오른쪽 `...` → **Share**
   - 팀원 이메일로 초대 링크 전송
   - 팀원을 내 Tailscale 네트워크에 사용자로 추가하는 게 아니라, **이 PC 한 대만** 공유하는 방식이다. 팀원은 호스트 PC 외에는 접근할 수 없다.
5. Windows 절전 끄기: 설정 → 시스템 → 전원 → 화면/절전 → 절전 모드 **없음** (공용 서버로 쓰는 동안만)

## 2. 공용 모드로 실행 (호스트 PC)

```
docker compose -f docker-compose.yml -f docker-compose.shared.yml up -d
```

- 평소 로컬 개발은 기존처럼 `docker compose up -d` (내 PC에서만 접속 가능)
- `TAILSCALE_IP` 가 비어 있으면 실행 전에 오류로 알려준다.
- Tailscale이 켜진 뒤에 실행해야 한다. (꺼져 있으면 포트 연결 실패)

## 3. 팀원 접속 방법

1. Tailscale 설치 → 로그인 → 호스트가 보낸 공유 초대 수락
2. 브라우저 / 코드에서 아래 주소로 접속 (`100.x.x.x` 는 호스트 주소)

| 서비스 | 주소 | 누가 주로 쓰나 |
|---|---|---|
| Kibana | `http://100.x.x.x:5601` | 김연서 (대시보드) |
| Elasticsearch | `http://100.x.x.x:9200` | 우주연 (매핑), 김하연 (탐지 스크립트) |
| 테스트 웹앱 | `http://100.x.x.x:8080` | 전원 (트래픽 발생) |

> 탐지 스크립트 등 코드에는 ES 주소를 직접 쓰지 말고 환경 변수(예: `ES_HOST`)로 받는다.
> 로컬에서는 `http://localhost:9200`, 공용 서버에서는 `http://100.x.x.x:9200`.

## 4. 공용 서버 사용 규칙

- 공용 서버에는 **main 에 병합된 코드만** 반영한다. 호스트에서 직접 설정을 고치지 않는다.
- 재시작·데이터 삭제가 필요하면 **Discord에 먼저 공지**한다.
- 테스트 데이터가 섞이지 않게, 테스트할 때 Discord에 "OO 테스트 중 (시간)"을 남긴다.
- 공격 재현 스크립트는 공용 서버 주소(`100.x.x.x`)와 로컬에만 실행한다.

## 5. 보안 메모

- 현재 ES·Kibana 로그인(xpack.security)은 꺼져 있다. 대신 **Tailscale로 공유받은 팀원만** 접속할 수 있고, 인터넷에는 열려 있지 않다.
- 클라우드(EC2 등)로 옮길 때는 반드시 ES 보안을 켜고 비밀번호를 `.env` 로 관리한다. (`docs/infra-roadmap.md` EC2 체크리스트)
- Tailscale 공유를 해제하면 해당 팀원의 접속이 즉시 끊긴다. 프로젝트가 끝나면 공유를 해제한다.
