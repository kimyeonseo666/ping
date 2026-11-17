from datetime import datetime, timedelta

# ==========================================
# 1. 탐지기 설정값 (상수) - 문서 명세 기준
# ==========================================
LOGIN_PATH = "/api/login"       # 로그인 처리 경로 (문서 기준)
LOGIN_METHOD = "POST"           # 로그인 시도로 인정할 HTTP 방식

ADMIN_USERS = ["admin", "root", "administrator", "master", "system"]  # 관리자 계정 목록

SHORT_WINDOW_SECONDS = 60       # 최근 1분 (60초)
LONG_WINDOW_SECONDS = 300       # 최근 5분 (300초)

# 1분 기준 실패 횟수 임계값
level1_1M = 5                  # 1분 내 5회 이상 (관찰)
level2_1M = 10                 # 1분 내 10회 이상 (경고)
level3_1M = 20                   # 1분 내 20회 이상 (알림)
level4_1M = 30                   # 1분 내 30회 이상 (차단)

# 5분 기준 실패 횟수 임계값
level1_5M = 20                 # 5분 내 15회 이상 (관찰)
level2_5M = 40                 # 5분 내 30회 이상 (경고)
level3_5M = 70                   # 5분 내 60회 이상 (알림)
level4_5M = 100                  # 5분 내 100회 이상 (차단)

# ==========================================
# 2. 탐지기 내부 상태 저장소
# Key: (client_ip, user_id)
# ==========================================
bruteforce_state = {}


def process_login_log(log):
    """
    한 건의 전처리된 로그인 로그(Dict)를 입력받아 브루트포스 공격을 탐지하는 함수
    - 1분 및 5분 슬라이딩 윈도우 동시 계산
    - 두 기준 중 더 높은 위험도를 최종 선택
    - 위험 등급이 '상승'한 경우에만 탐지 이벤트 생성 (중복 이벤트 생성 방지)
    """
    # --------------------------------------------------
    # 1. 로그인 요청 및 실패 여부 검사
    # --------------------------------------------------
    path = log.get("path") or log.get("request_uri") or log.get("uri")
    method = log.get("method")
    status_code = log.get("status_code") or log.get("status")
    login_result = log.get("login_result")

    # POST /login 요청인지 확인
    is_login_path = (path == LOGIN_PATH) and (method == LOGIN_METHOD)
    # 로그인 실패 판정 (status_code 401/403 또는 login_result == 'failure')
    is_failure = (login_result == "failure") or (status_code in [401, 403])

    if not (is_login_path and is_failure):
        return None  # 로그인 실패 요청이 아니면 검사하지 않고 종료

    # 핵심 분석 키: 동일 IP + 동일 계정 ID 조합
    client_ip = log.get("client_ip") or log.get("source_ip") or "127.0.0.1"
    user_id = log.get("user_id") or "unknown"
    state_key = (client_ip, user_id)

    # 타임스탬프 파싱
    raw_timestamp = log.get("@timestamp") or log.get("timestamp") or datetime.now().isoformat()
    try:
        log_time = datetime.fromisoformat(raw_timestamp)
    except (ValueError, TypeError):
        log_time = datetime.now()

    # --------------------------------------------------
    # 2. 내부 상태 초기화
    # --------------------------------------------------
    if state_key not in bruteforce_state:
        bruteforce_state[state_key] = {
            "level": "NONE",
            "failures": [],
            "first_failure_at": raw_timestamp
        }

    state = bruteforce_state[state_key]
    state["failures"].append(log_time)
    state["last_failure_at"] = raw_timestamp

    # --------------------------------------------------
    # 3. 1분 및 5분 슬라이딩 윈도우 정제 (5분이 지난 기록 제거)
    # --------------------------------------------------
    cutoff_5m = log_time - timedelta(seconds=LONG_WINDOW_SECONDS)
    cutoff_1m = log_time - timedelta(seconds=SHORT_WINDOW_SECONDS)

    # 5분 이상 지난 기록 전체 제거
    state["failures"] = [t for t in state["failures"] if t > cutoff_5m]

    # 1분 내 / 5분 내 실패 횟수 계산
    count_5m = len(state["failures"])
    count_1m = len([t for t in state["failures"] if t > cutoff_1m])

    # --------------------------------------------------
    # 4. 기본 점수 산정 (Base Score)
    # --------------------------------------------------
    is_admin = user_id.lower() in ADMIN_USERS
    base_score = 45 if is_admin else 30  # 관리자 45점 / 일반 계정 30점

    # --------------------------------------------------
    # 5. 가중치 점수 산정 (Weight Score)
    # --------------------------------------------------
    weight_score = 0
    if count_1m >= level4_1M or count_5m >= level4_5M:
        weight_score += 20
    elif count_1m >= level3_1M or count_5m >= level3_5M:
        weight_score += 15
    elif count_1m >= level2_1M or count_5m >= level2_5M:
        weight_score += 10
    elif count_1m >= level1_1M or count_5m >= level1_5M:
        weight_score += 5

    # 다른 공격 연계 여부 체크 (로그 내 연계 정보가 있을 경우 +15점)
    if log.get("linked_attack") is True:
        weight_score += 15

    # 최종 위험점수 계산 (최대 100점 산한)
    risk_score = min(100, base_score + weight_score)

    # --------------------------------------------------
    # 6. 위험점수에 따른 공통 위험도 (Severity) 및 대응 (Action) 판정
    # --------------------------------------------------
    if risk_score >= 75:
        new_severity = "CRITICAL"
        action = "BLOCK"
    elif risk_score >= 50:
        new_severity = "HIGH"
        action = "BLOCK_CANDIDATE"
    elif risk_score >= 25:
        new_severity = "MEDIUM"
        action = "ALERT"
    else:
        new_severity = "LOW"
        action = "RECORD"

    # --------------------------------------------------
    # 7. 위험 등급 상승 시에만 새 탐지 이벤트 생성
    # --------------------------------------------------
    levels = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if levels.index(new_severity) > levels.index(state.get("level", "NONE")):
        state["level"] = new_severity  # 위험도 갱신

        detection_event = {
            "attack_type": "BRUTE_FORCE",
            "severity": new_severity,
            "action": action,
            "risk_score": risk_score,
            "base_score": base_score,
            "weight_score": weight_score,
            "client_ip": client_ip,
            "user_id": user_id,
            "is_admin_target": is_admin,
            "login_path": path,
            "failure_count_1m": count_1m,
            "failure_count_5m": count_5m,
            "detected_at": raw_timestamp,
            "reason": f"기본점수 {base_score}점 + 가중치 {weight_score}점 (총점: {risk_score}점 / {new_severity})"
        }
        return detection_event