import re
from urllib.parse import unquote
from datetime import datetime, timedelta

# ==========================================
# 1. 탐지기 설정값 
# ==========================================
REPEAT_WINDOW_SECONDS = 60         # 반복 SQLi 시간 창: 1분
REPEAT_THRESHOLD = 3               # 1분 내 3회 이상 시 반복 공격 가중치
SPREAD_WINDOW_SECONDS = 600        # 경로 확산 확인 시간 창: 10분
SPREAD_PATH_THRESHOLD = 3          # 10분 내 서로 다른 경로 3개 이상 시 확산 가중치
TIME_SQLI_THRESHOLD = 3.0          # 시간 기반 SQLi 응답 지연 기준: 3.0초
LARGE_RESPONSE_MIN_BYTES = 1048576 # 대량 응답 기준: 1MB
MAX_RISK_SCORE = 100               # 위험점수 상한값

# 관리자·인증·회원 관련 중요 경로
HIGH_RISK_PATHS = ["/login", "/api/login", "/admin", "/users", "/api/admin"]
# 개인정보·인증정보 조회 관련 경로 키워드
PRIVACY_PATH_KEYWORDS = ["/users", "/member", "/profile", "/account", "/login", "/auth"]

# SQLi 정규표현식 패턴 (디코딩 & 소문자 변환 후 검사)
PATTERNS = {
    "SQLI-01_AUTH_BYPASS": re.compile(
        r"(['\"`]\s*(or|and)\s*['\"`0-9a-z]+=|(\bor\b|\band\b)\s+1\s*=\s*1|['\"`]\s*(--|#|/\*))",
        re.IGNORECASE
    ),
    "SQLI-02_UNION_SELECT": re.compile(
        r"\bunion\s+(all\s+)?select\b|\binformation_schema\b|\b(table_name|column_name|database\(\)|version\(\)|user\(\))\b",
        re.IGNORECASE
    ),
    "SQLI-03_TIME_BASED": re.compile(
        r"\b(sleep|benchmark)\s*\(|\bwaitfor\s+delay\b",
        re.IGNORECASE
    ),
    "SQLI-03_COMMENT_INJECTION": re.compile(
        r"(--\s*$|#\s*$|/\*.*\*/)",
        re.IGNORECASE
    )
}

# ==========================================
# 2. 탐지기 내부 메모리 상태 저장소
# ==========================================
# Key: client_ip, Value: dict(1분/10분 시도 이력, 접근 경로, 현재 최고 등급)
sqli_state = {}


def decode_payload(raw_text):
    """
    URL 인코딩 및 이중 인코딩(%2527 -> %27 -> ')을 최대 2회 디코딩 후 소문자화
    """

    if not raw_text:
        return ""
    text = str(raw_text)
    decoded_once = unquote(text)
    # 1회 디코딩 후에도 %가 남아있으면 한 번 더 디코딩 (이중 인코딩 대응)
    decoded_twice = unquote(decoded_once) if "%" in decoded_once else decoded_once
    return decoded_twice.lower().strip()


def process_sqli_log(log):
    """
    전처리된 로그 1건을 받아 SQL Injection 여부를 탐지하고,
    위험 등급 상승 또는 성공 의심 시 탐지 이벤트를 반환
    """
    # 1. 입력값 추출 (query_string, request_body 우선, path 보조)
    path = log.get("path") or ""
    query_string = log.get("query_string") or ""
    request_body = log.get("request_body") or ""

    # 원문 + 디코딩 문자열 모두 준비
    raw_combined = f"{path} {query_string} {request_body}".lower()
    decoded_combined = f"{decode_payload(path)} {decode_payload(query_string)} {decode_payload(request_body)}"
    target_text = f"{raw_combined} {decoded_combined}"

    # 2. SQLi 패턴 매칭
    matched_rules = []
    for rule_id, regex in PATTERNS.items():
        if regex.search(target_text):
            matched_rules.append(rule_id)

    # 패턴이 하나도 안 잡히면 정상 요청으로 간주하고 종료
    if not matched_rules:
        return None

    # 3. 응답 정보 및 추가 규칙(SQLI-03 시간지연, SQLI-04 서버오류, SQLI-05 인증우회) 확인
    status_code = int(log.get("status_code") or log.get("status") or 200)
    response_time = float(log.get("response_time") or 0.0)
    response_size = int(log.get("response_size") or 0)
    login_result = log.get("login_result")
    response_inspection = log.get("response_inspection") or []
    sensitive_data_type = log.get("sensitive_data_type") or []

    # SQLI-03 보완: 시간 지연 패턴 + 실제 응답시간 3초 이상
    is_slow_sqli = ("SQLI-03_TIME_BASED" in matched_rules) and (response_time >= TIME_SQLI_THRESHOLD)

    # SQLI-04: SQLi 시도 후 5xx 서버 오류 발생
    if 500 <= status_code < 600:
        matched_rules.append("SQLI-04_SERVER_ERROR")

    # SQLI-05: 인증 경로에서 SQLi 패턴 후 로그인 성공
    is_auth_path = any(p in path for p in ["/login", "/api/login", "/auth"])
    if is_auth_path and login_result == "success":
        matched_rules.append("SQLI-05_AUTH_BYPASS_SUCCESS")

    # 4. 성공 의심 정황 판별 -> 기본 점수(Base Score: 55점 vs 85점) 결정
    success_indicators = []
    if "SQLI-05_AUTH_BYPASS_SUCCESS" in matched_rules:
        success_indicators.append("login_success")
    if any(x in response_inspection for x in ["db_error", "sql_error", "credential_pattern", "personal_data_pattern"]):
        success_indicators.extend([x for x in response_inspection if x != "none"])
    if sensitive_data_type:
        success_indicators.extend(sensitive_data_type)
    if response_size >= LARGE_RESPONSE_MIN_BYTES or "large_response" in response_inspection:
        success_indicators.append("large_response_exposed")

    success_suspected = len(success_indicators) > 0
    base_score = 85 if success_suspected else 55

    # 5. IP별 내부 상태(1분 반복 / 10분 경로 확산) 갱신
    client_ip = log.get("client_ip") or log.get("source_ip") or "127.0.0.1"
    raw_timestamp = log.get("@timestamp") or log.get("timestamp") or datetime.now().isoformat()
    try:
        log_time = datetime.fromisoformat(raw_timestamp)
    except (ValueError, TypeError):
        log_time = datetime.now()

    if client_ip not in sqli_state:
        sqli_state[client_ip] = {
            "level": "NONE",
            "attempts": []  # [{"time": datetime, "path": str}]
        }

    state = sqli_state[client_ip]
    state["attempts"].append({"time": log_time, "path": path})

    # 10분(600초) 지난 기록 정리
    cutoff_10m = log_time - timedelta(seconds=SPREAD_WINDOW_SECONDS)
    cutoff_1m = log_time - timedelta(seconds=REPEAT_WINDOW_SECONDS)
    state["attempts"] = [a for a in state["attempts"] if a["time"] > cutoff_10m]

    attempts_1m = [a for a in state["attempts"] if a["time"] > cutoff_1m]
    count_1m = len(attempts_1m)
    distinct_paths_10m = list({a["path"] for a in state["attempts"]})

    # 6. 가중치 점수(Weight Score) 계산
    weight_details = {}

    # (1) 반복 공격: 1분 내 3회 이상 (+10)
    if count_1m >= REPEAT_THRESHOLD:
        weight_details["repeat_1m"] = 10

    # (2) 여러 경로 확산: 10분 내 서로 다른 경로 3개 이상 (+10)
    if len(distinct_paths_10m) >= SPREAD_PATH_THRESHOLD:
        weight_details["path_spread_10m"] = 10

    # (3) 관리자·인증 중요 경로 대상 (+15)
    if any(path.startswith(hrp) for hrp in HIGH_RISK_PATHS):
        weight_details["high_risk_path"] = 15

    # (4) 비정상 응답: 5xx 오류 또는 시간지연 SQLi + 3초 이상 응답 (+25)
    if (500 <= status_code < 600) or is_slow_sqli:
        weight_details["abnormal_response"] = 25

    # (5) 개인정보·인증정보 관련 기능 대상 (+25)
    if any(kw in path.lower() for kw in PRIVACY_PATH_KEYWORDS):
        weight_details["privacy_or_auth_target"] = 25

    # (6) 직전 10분 내 다른 공격(Scanning, BruteForce 등) 연계 (+15)
    if log.get("linked_attack") is True:
        weight_details["linked_attack"] = 15

    weight_score = sum(weight_details.values())
    risk_score = min(MAX_RISK_SCORE, base_score + weight_score)

    # 7. 위험점수 -> 위험도(Severity) & 1차 Action 매핑
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

    # 8. 중복 이벤트 방지 (위험 등급이 상승했거나, 성공 의심 정황이 새로 포착된 경우 반환)
    levels = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    current_level = state.get("level", "NONE")

    if levels.index(new_severity) > levels.index(current_level) or success_suspected:
        if levels.index(new_severity) > levels.index(current_level):
            state["level"] = new_severity

        detection_event = {
            "attack_type": "SQL_INJECTION",
            "severity": new_severity,
            "action": action,
            "risk_score": risk_score,
            "base_score": base_score,
            "weight_score": weight_score,
            "weight_details": weight_details,
            "client_ip": client_ip,
            "user_id": log.get("user_id"),
            "target_path": path,
            "matched_rules": list(dict.fromkeys(matched_rules)),  # 중복 제거
            "success_suspected": success_suspected,
            "success_indicators": success_indicators,
            "attempt_count_1m": count_1m,
            "distinct_path_count_10m": len(distinct_paths_10m),
            "response_time": response_time,
            "response_size": response_size,
            "detected_at": raw_timestamp,
            "reason": f"SQLi 패턴 탐지({', '.join(matched_rules)}) | 기본 {base_score}점 + 가중치 {weight_score}점 = {risk_score}점 ({new_severity})"
        }
        return detection_event

    return None