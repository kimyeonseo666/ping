<!--
PR 제목과 커밋 메시지 말머리 (Conventional Commits)
  feat:     새 기능            예) feat: 로그인 실패 시 401 반환
  fix:      버그 수정          예) fix: Filebeat 권한 오류 수정
  docs:     문서만 변경        예) docs: 로그 포맷 설계서 추가
  chore:    설정·빌드·잡무     예) chore: docker-compose 버전 고정
  refactor: 동작 변화 없는 코드 정리
  test:     테스트 추가·수정
-->

## 작업 내용
<!-- 무엇을 바꿨는지 한두 줄 + 주요 변경 사항 -->
- 

## 관련 이슈
<!-- 병합되면 이슈가 자동으로 닫힙니다. 예: Closes #1 -->
Closes #

## 변경 영역
<!-- 해당하는 곳에 x 표시 -->
- [ ] 수집/인프라 (nginx, filebeat, docker-compose, app)
- [ ] 저장/파이프라인 (logstash, elasticsearch)
- [ ] 탐지 로직 (detection)
- [ ] 대시보드 (dashboard)
- [ ] 공격 재현 (attack-scripts)
- [ ] 문서 (docs)

## 확인 방법
<!-- 리뷰어가 따라 해볼 수 있게 적어 주세요. 예: docker compose up -d → python scripts/smoke_test.py -->
1. 
2. 

## 다른 파트에 영향
<!-- 로그 필드명, 인덱스 이름, 포트 등 다른 팀원 작업에 영향을 주는 변경이 있으면 적어 주세요. 없으면 "없음" -->


## 리뷰어에게
<!-- 특히 봐줬으면 하는 부분, 고민한 점, 아직 남은 작업 -->


## 체크리스트
- [ ] `main` 이 아닌 작업 브랜치에서 `main` 으로 보내는 PR이다
- [ ] PR 제목과 커밋 메시지가 말머리 규칙(`feat:` / `fix:` / `docs:` / `chore:` / `refactor:` / `test:`)을 따른다
- [ ] 내 담당 폴더만 수정했다 (다른 파트를 수정했다면 위에 이유를 적었다)
- [ ] 로컬에서 실행해 동작을 확인했다
- [ ] 비밀번호, 개인 로그 파일(`logs/`), `.venv/` 등을 올리지 않았다
