import os
from datetime import datetime, timedelta
from urllib.parse import urlparse

# ==========================================
# 1. 탐지기 설정값 (상수)
# ==========================================
SCANNING_WINDOW_SECONDS = 60  # 최근 1분(60초) 슬라이딩 윈도우

# 정적 파일 / 일반 자동 요청 경로 (집계 제외)
STATIC_EXTENSIONS = [
    ".css", ".js", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot"
]
EXCLUDED_PATHS = [
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml"
]

# 탐지기 1: 고유 path 급증 임계값
UNIQUE_PATH_OBSERVE = 5
UNIQUE_PATH_WARNING = 10
UNIQUE_PATH_ALERT = 20
UNIQUE_PATH_BLOCK = 30

# 탐지기 2: 404 응답 임계값값
NOT_FOUND_OBSERVE = 3
NOT_FOUND_WARNING = 6
NOT_FOUND_ALERT = 12
NOT_FOUND_RATIO_ALERT = 0.70

# 탐지기 3: 민감 경로 목록
GENERAL_PROTECTED_PATHS = [
    "/admin", "/administrator", "/manager", "/wp-admin", "/login"
]
HIGH_RISK_PATH_KEYWORDS = [
    "/.env", "/.git", "/.svn", "/backup", "/backups",
    "/config", "/phpmyadmin", "/server-status", "/debug", "/phpinfo.php"
]

# 탐지기 4: User-Agent 목록
KNOWN_SCANNER_UA = ["nikto", "gobuster", "dirbuster", "ffuf", "wpscan", "sqlmap", "nmap"]
AUTOMATION_UA = ["curl", "wget", "python-requests", "go-http-client"]

# 탐지기 5: 정찰성 HTTP 메서드
RECON_METHODS = ["HEAD", "OPTIONS", "TRACE", "PROPFIND"]

# 탐지기 6: URL 패턴 다양성 (민감 확장자)
SENSITIVE_FILE_EXTENSIONS = [".bak", ".old", ".orig", ".zip", ".tar", ".gz", ".sql", ".swp"]

# 자동화 보조 판단 기준
FAST_INTERVAL_SECONDS = 3
MIN_PATHS_FOR_AUTOMATION = 10

# IP별 스캐닝 상태 저장소
scanning_state = {}
event_counter = 0


def _normalize_path(raw_path: str) -> str:
    """쿼리스트링 제거, 소문자화, 끝 '/' 제거 (단, 루트 '/'는 유지)"""
    if not raw_path:
        return "/"
    parsed = urlparse(raw_path).path.lower()
    if len(parsed) > 1 and parsed.endswith("/"):
        parsed = parsed.rstrip("/")
    return parsed or "/"


def _is_static_or_excluded(norm_path: str) -> bool:
    """정적 리소스 또는 예외 경로인지 확인"""
    if norm_path in EXCLUDED_PATHS:
        return True
    _, ext = os.path.splitext(norm_path)
    return ext in STATIC_EXTENSIONS


def _get_path_base(norm_path: str) -> str:
    """URL 변형 탐지용 기반 이름 추출 (예: /admin.php -> admin)"""
    basename = os.path.basename(norm_path)
    base, _ = os.path.splitext(basename)
    return base


def process_scanning_log(log: dict):
    """
    한 건의 정규화된 웹 로그를 전달받아 스캐닝 여부를 점수제로 분석하고,
    위험 등급 상승 시 탐지 이벤트 반환.
    """
    global event_counter

    raw_path = log.get("path") or log.get("request_uri") or "/"
    norm_path = _normalize_path(raw_path)

    # 1. 정적 파일 및 제외 경로 필터링
    if _is_static_or_excluded(norm_path):
        return None

    client_ip = log.get("client_ip") or log.get("source_ip") or "127.0.0.1"
    method = (log.get("method") or "GET").upper()
    status_code = int(log.get("status_code") or log.get("status") or 200)
    user_agent = log.get("user_agent") or ""
    ua_lower = user_agent.lower()

    raw_timestamp = log.get("@timestamp") or log.get("timestamp") or datetime.now().isoformat()
    try:
        log_time = datetime.fromisoformat(raw_timestamp)
    except (ValueError, TypeError):
        log_time = datetime.now()

    # 2. 경로 특성 분석
    is_general_protected = any(norm_path == p or norm_path.startswith(p + "/") for p in GENERAL_PROTECTED_PATHS)
    is_high_risk = any(kw in norm_path for kw in HIGH_RISK_PATH_KEYWORDS)
    _, ext = os.path.splitext(norm_path)
    has_sensitive_ext = ext in SENSITIVE_FILE_EXTENSIONS
    path_base = _get_path_base(norm_path)

    # 3. IP별 내부 상태 초기화 및 1분 슬라이딩 윈도우 갱신
    if client_ip not in scanning_state:
        scanning_state[client_ip] = {
            "level": "NONE",
            "first_seen_at": raw_timestamp,
            "last_seen_at": raw_timestamp,
            "requests_1m": [],
            "last_alert_at": None
        }

    state = scanning_state[client_ip]
    state["requests_1m"].append({
        "time_obj": log_time,
        "timestamp": raw_timestamp,
        "request_id": log.get("request_id"),
        "normalized_path": norm_path,
        "status_code": status_code,
        "method": method,
        "user_agent": user_agent,
        "ua_lower": ua_lower,
        "is_general_protected": is_general_protected,
        "is_high_risk": is_high_risk,
        "has_sensitive_ext": has_sensitive_ext,
        "path_base": path_base
    })

    cutoff_time = log_time - timedelta(seconds=SCANNING_WINDOW_SECONDS)
    state["requests_1m"] = [r for r in state["requests_1m"] if r["time_obj"] > cutoff_time]

    reqs = state["requests_1m"]
    req_count = len(reqs)
    state["first_seen_at"] = reqs[0]["timestamp"]
    state["last_seen_at"] = reqs[-1]["timestamp"]

    # 4. 지표 집계
    unique_paths = set(r["normalized_path"] for r in reqs)
    unique_path_count = len(unique_paths)

    paths_404 = set(r["normalized_path"] for r in reqs if r["status_code"] == 404)
    paths_401_403 = set(r["normalized_path"] for r in reqs if r["status_code"] in (401, 403))
    count_404 = sum(1 for r in reqs if r["status_code"] == 404)
    count_403 = sum(1 for r in reqs if r["status_code"] == 403)
    count_401 = sum(1 for r in reqs if r["status_code"] == 401)
    ratio_404 = round(count_404 / req_count, 2) if req_count > 0 else 0.0

    general_paths_hit = set(r["normalized_path"] for r in reqs if r["is_general_protected"])
    high_risk_paths_hit = sorted(list(set(r["normalized_path"] for r in reqs if r["is_high_risk"])))

    # 평균 요청 간격 계산
    if req_count > 1:
        duration = (reqs[-1]["time_obj"] - reqs[0]["time_obj"]).total_seconds()
        avg_interval = round(duration / (req_count - 1), 2)
    else:
        avg_interval = 0.0

    # ==========================================
    # 5. 세부 탐지기(1~6)별 가중치 계산 (탐지기별 최고점 1개 적용)
    # ==========================================
    # [탐지기 1] 고유 URL 급증 탐지
    d1_score = 0
    if unique_path_count >= UNIQUE_PATH_BLOCK:
        d1_score = 20
    elif unique_path_count >= UNIQUE_PATH_ALERT:
        d1_score = 15
    elif unique_path_count >= UNIQUE_PATH_WARNING:
        d1_score = 10
    elif unique_path_count >= UNIQUE_PATH_OBSERVE:
        d1_score = 5

    # [탐지기 2] 실패/차단 응답 탐지
    d2_candidates = [0]
    if len(paths_404) >= NOT_FOUND_ALERT or (ratio_404 >= NOT_FOUND_RATIO_ALERT and unique_path_count >= 10):
        d2_candidates.append(15)
    elif len(paths_404) >= NOT_FOUND_WARNING:
        d2_candidates.append(10)
    elif len(paths_404) >= NOT_FOUND_OBSERVE:
        d2_candidates.append(5)
    if len(paths_401_403) >= 5:
        d2_candidates.append(5)
    d2_score = max(d2_candidates)

    # [탐지기 3] 민감 경로 탐지지
    d3_candidates = [0]
    hr_count = len(high_risk_paths_hit)
    has_env = any("/.env" in p for p in high_risk_paths_hit)
    has_git = any("/.git" in p for p in high_risk_paths_hit)
    has_backup = any("/backup" in p for p in high_risk_paths_hit)
    categories_hit = sum([has_env, has_git, has_backup])

    if hr_count >= 3 or categories_hit >= 2:
        d3_candidates.append(20)
    elif hr_count == 2:
        d3_candidates.append(15)
    elif hr_count == 1:
        d3_candidates.append(10)
    if len(general_paths_hit) >= 2:
        d3_candidates.append(5)
    d3_score = max(d3_candidates)

    # [탐지기 4] 자동화 도구 흔적 탐지 (User-Agent)
    d4_candidates = [0]
    ua_type = "BROWSER"
    if not user_agent.strip():
        ua_type = "MISSING"
    elif any(s in ua_lower for s in KNOWN_SCANNER_UA):
        ua_type = "KNOWN_SCANNER"
        d4_candidates.append(10)
    elif any(a in ua_lower for a in AUTOMATION_UA):
        ua_type = "AUTOMATION_CLIENT"
        d4_candidates.append(2)
        if unique_path_count >= MIN_PATHS_FOR_AUTOMATION and avg_interval <= FAST_INTERVAL_SECONDS:
            d4_candidates.append(5)
    d4_score = max(d4_candidates)

    # [탐지기 5] HTTP 메서드 정찰 탐지
    d5_candidates = [0]
    recon_reqs = [r for r in reqs if r["method"] in RECON_METHODS]
    suspicious_methods = sorted(list(set(r["method"] for r in recon_reqs)))
    head_paths = set(r["normalized_path"] for r in reqs if r["method"] == "HEAD")
    opt_paths = set(r["normalized_path"] for r in reqs if r["method"] == "OPTIONS")

    if any(m in suspicious_methods for m in ("TRACE", "PROPFIND")):
        d5_candidates.append(10)
    if len(head_paths) >= 3 or len(opt_paths) >= 3:
        d5_candidates.append(5)
    d5_score = max(d5_candidates)

    # [탐지기 6] URL 패턴 다양성 (동일 기반 이름 변형 탐색)
    base_to_paths = {}
    for r in reqs:
        if r["path_base"]:
            base_to_paths.setdefault(r["path_base"], set()).add(r["normalized_path"])
    varied_bases = sorted([b for b, p_set in base_to_paths.items() if len(p_set) >= 3])
    variation_count = sum(len(base_to_paths[b]) for b in varied_bases)
    d6_score = 5 if varied_bases else 0

    weight_score = d1_score + d2_score + d3_score + d4_score + d5_score + d6_score

    # 기본 점수 산정 (탐지 징후가 있을 때 부여: 고위험 경로 포함 시 25점, 일반 15점)
    if weight_score == 0:
        return None
    base_score = 25 if (hr_count > 0 or len(general_paths_hit) > 0) else 15

    # 타 공격 연계 가중치 (+15점)
    linked_score = 15 if log.get("linked_attack") is True else 0
    total_score = min(100, base_score + weight_score + linked_score)

    # ==========================================
    # 6. 공통 위험도(Severity) 판정 (LOW / MEDIUM / HIGH / CRITICAL)
    # ==========================================
    if total_score >= 75:
        new_severity = "CRITICAL"
    elif total_score >= 50:
        new_severity = "HIGH"
    elif total_score >= 25:
        new_severity = "MEDIUM"
    else:
        new_severity = "LOW"

    # 7. 위험 등급 상승 시에만 탐지 이벤트 생성 (중복 방지)
    levels = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if levels.index(new_severity) > levels.index(state["level"]):
        state["level"] = new_severity
        if new_severity in ("HIGH", "CRITICAL"):
            state["last_alert_at"] = raw_timestamp

        event_counter += 1
        detection_event = {
            "event_id": f"det-scanning-{event_counter:06d}",
            "detected_at": raw_timestamp,
            "attack_type": "SCANNING",
            "severity": new_severity,
            "client_ip": client_ip,
            "user_id": None,
            "rule_name": f"SCANNING_SCORE_1M_{total_score}",
            "action": "RECORD",  # action 모듈에서 위험도별 정책으로 덮어씀
            "status": "active",
            "reason": (
                f"기본 {base_score}점 + 가중치 {weight_score}점"
                f"{f' + 연계 {linked_score}점' if linked_score else ''} "
                f"(총점: {total_score}점 / 고유경로 {unique_path_count}개, 404 {count_404}건)"
            ),
            "details": {
                "window_seconds": SCANNING_WINDOW_SECONDS,
                "first_seen_at": state["first_seen_at"],
                "last_seen_at": state["last_seen_at"],
                "request_count_1m": req_count,
                "unique_path_count_1m": unique_path_count,
                "status_404_count_1m": count_404,
                "status_403_count_1m": count_403,
                "status_401_count_1m": count_401,
                "error_response_ratio_1m": ratio_404,
                "general_protected_path_count_1m": len(general_paths_hit),
                "high_risk_path_count_1m": hr_count,
                "high_risk_paths": high_risk_paths_hit,
                "scanner_user_agent_type": ua_type,
                "scanner_user_agent": user_agent,
                "suspicious_method_count_1m": len(recon_reqs),
                "suspicious_methods": suspicious_methods,
                "url_pattern_variation_count_1m": variation_count,
                "url_pattern_bases": varied_bases,
                "avg_request_interval_sec": avg_interval,
                "score": total_score
            }
        }
        return detection_event

    return None