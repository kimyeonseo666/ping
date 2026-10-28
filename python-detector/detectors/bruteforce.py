from datetime import datetime, timedelta

# ==========================================
# 1. 탐지기 설정값 (상수) - 문서 명세 기준
# ==========================================
LOGIN_PATH = "/login"           # 로그인 처리 경로 (문서 기준)
LOGIN_METHOD = "POST"           # 로그인 시도로 인정할 HTTP 방식

SHORT_WINDOW_SECONDS = 60       # 최근 1분 (60초)
LONG_WINDOW_SECONDS = 300       # 최근 5분 (300초)

# 1분 기준 실패 횟수 임계값
OBSERVE_1M = 5                  # 1분 내 5회 이상 (관찰)
WARNING_1M = 10                 # 1분 내 10회 이상 (경고)
ALERT_1M = 20                   # 1분 내 20회 이상 (알림)
BLOCK_1M = 30                   # 1분 내 30회 이상 (차단)

# 5분 기준 실패 횟수 임계값
OBSERVE_5M = 20                 # 5분 내 15회 이상 (관찰)
WARNING_5M = 40                 # 5분 내 30회 이상 (경고)
ALERT_5M = 70                   # 5분 내 60회 이상 (알림)
BLOCK_5M = 100                  # 5분 내 100회 이상 (차단)

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
    raw_timestamp = log.get("timestamp") or log.get("@timestamp")
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
    # 4. 1분 기준 및 5분 기준 위험도 각자 계산
    # --------------------------------------------------
    # (1분 기준 위험도)
    level_1m = "NONE"
    if count_1m >= BLOCK_1M:
        level_1m = "BLOCK"
    elif count_1m >= ALERT_1M:
        level_1m = "ALERT"
    elif count_1m >= WARNING_1M:
        level_1m = "WARNING"
    elif count_1m >= OBSERVE_1M:
        level_1m = "OBSERVE"

    # (5분 기준 위험도)
    level_5m = "NONE"
    if count_5m >= BLOCK_5M:
        level_5m = "BLOCK"
    elif count_5m >= ALERT_5M:
        level_5m = "ALERT"
    elif count_5m >= WARNING_5M:
        level_5m = "WARNING"
    elif count_5m >= OBSERVE_5M:
        level_5m = "OBSERVE"

    # --------------------------------------------------
    # 5. 둘 중 더 높은 위험도(Severity) 선택 및 대응(Action) 결정
    # --------------------------------------------------
    levels = ["NONE", "OBSERVE", "WARNING", "ALERT", "BLOCK"]
    idx_1m = levels.index(level_1m)
    idx_5m = levels.index(level_5m)

    # 더 높은 위험도 선택
    if idx_1m >= idx_5m:
        new_level = level_1m
    else:
        new_level = level_5m

    # 위험도에 대응하는 Action 결정
    action_map = {
        "NONE": "RECORD",
        "OBSERVE": "RECORD",
        "WARNING": "ALERT",
        "ALERT": "BLOCK_CANDIDATE",
        "BLOCK": "BLOCK"
    }
    action = action_map.get(new_level, "RECORD")

    # --------------------------------------------------
    # 6. 위험 등급 상승 시에만 새 탐지 이벤트 생성
    # --------------------------------------------------
    current_level_idx = levels.index(state["level"])
    new_level_idx = levels.index(new_level)

    if new_level_idx > current_level_idx:
        state["level"] = new_level  # 현재 등급 업데이트

        detection_event = {
            "attack_type": "BRUTE_FORCE",
            "severity": new_level,
            "action": action,
            "client_ip": client_ip,
            "user_id": user_id,
            "login_path": path,
            "failure_count_1m": count_1m,
            "failure_count_5m": count_5m,
            "detected_at": raw_timestamp,
            "reason": f"1분 내 실패 {count_1m}회 / 5분 내 실패 {count_5m}회 발생 (위험도: {new_level})"
        }
        return detection_event

    return None