from datetime import datetime, timedelta

# 스캐닝 전용 대응 정책 및 대시보드 시각화 매핑
SCANNING_ACTION_POLICY = {
    "LOW": {
        "action": "RECORD",
        "system_action": "원본 로그 저장",
        "action_guide": "별도 조치 없이 관찰",
        "dashboard_color": "blue",
        "dashboard_badge": "🟦 관찰 (LOW)",
        "dashboard_target": "일반 통계"
    },
    "MEDIUM": {
        "action": "ALERT",
        "system_action": "Scanning 탐지 이벤트 생성",
        "action_guide": "요청한 경로·상태 코드·탐지기별 점수를 확인하고 같은 IP의 후속 행위를 감시",
        "dashboard_color": "yellow",
        "dashboard_badge": "🟨 경고 (MEDIUM)",
        "dashboard_target": "경고 목록"
    },
    "HIGH": {
        "action": "BLOCK_CANDIDATE",
        "system_action": "고위험 탐지 이벤트 생성, 관리자 알림",
        "action_guide": "고위험 경로 접근 여부와 브루트포스·SQLi·Path Traversal 등 후속 공격 연계 여부를 조사. 차단 후보로 등록할지 검토",
        "dashboard_color": "orange",
        "dashboard_badge": "🟧 알림 (HIGH)",
        "dashboard_target": "알림 목록"
    },
    "CRITICAL": {
        "action": "BLOCK_CANDIDATE",  # 기본은 차단 후보, 확정 조건 충족 시 BLOCK으로 승격]
        "system_action": "긴급 이벤트 생성, 관리자 알림, 차단 후보 기록",
        "action_guide": "민감 경로 접근 성공 정황과 실제 데이터 노출 여부를 우선 조사. 관련 로그를 확인하고 필요하면 임시 차단을 검토",
        "dashboard_color": "red",
        "dashboard_badge": "🟥 긴급 (CRITICAL)",
        "dashboard_target": "긴급/차단 후보 목록"
    }
}

# 차단 예외 목록 (Allowlist) 및 기본 차단 시간(10분)
ALLOWLIST_IPS = {"127.0.0.1", "::1"}
BLOCK_DURATION_SECONDS = 600
block_counter = 0


def _check_block_confirmed(detection_event: dict) -> bool:
    """
    문서의 BLOCK 확정 조건 검증:
    - 고위험 노출 경로 3개 이상 요청
    - 최근 1분 고유 URL 수 30개 이상
    - 명확한 웹 스캐너 User-Agent + 고위험 경로 요청
    """
    details = detection_event.get("details", {})
    hr_count = details.get("high_risk_path_count_1m", 0)
    unique_paths = details.get("unique_path_count_1m", 0)
    ua_type = details.get("scanner_user_agent_type", "")

    if hr_count >= 3:
        return True
    if unique_paths >= 30:
        return True
    if ua_type == "KNOWN_SCANNER" and hr_count >= 1:
        return True
    return False


def apply_scanning_action(detection_event: dict):
    """
    scanning.py에서 생성된 탐지 이벤트를 받아 위험도별 대응 정책과
    대시보드 시각화 정보를 부착하고, 차단 확정 시 차단 이벤트도 생성합니다.
    """
    global block_counter

    if not detection_event:
        return None

    severity = detection_event.get("severity", "LOW")
    policy = SCANNING_ACTION_POLICY.get(severity, SCANNING_ACTION_POLICY["LOW"])

    action = policy["action"]
    system_action = policy["system_action"]
    action_guide = policy["action_guide"]
    block_event = None

    client_ip = detection_event.get("client_ip")

    # CRITICAL 등급이면서 차단 확정 조건 충족 + 예외 IP가 아닌 경우 BLOCK 승격
    if severity == "CRITICAL" and _check_block_confirmed(detection_event):
        if client_ip not in ALLOWLIST_IPS:
            action = "BLOCK"
            system_action = "긴급 탐지 이벤트 생성, 차단 이벤트 생성 및 10분 임시 차단 수행"

            block_counter += 1
            detected_dt = datetime.fromisoformat(detection_event["detected_at"])
            unblock_dt = detected_dt + timedelta(seconds=BLOCK_DURATION_SECONDS)

            block_event = {
                "block_id": f"block-{block_counter:06d}",
                "event_type": "BLOCK",
                "client_ip": client_ip,
                "attack_type": "SCANNING",
                "severity": "BLOCK",
                "reason": detection_event.get("reason", ""),
                "blocked_at": detected_dt.isoformat(),
                "unblock_at": unblock_dt.isoformat(),
                "status": "blocked",
                "detection_event_id": detection_event.get("event_id")
            }

    # 탐지 이벤트에 대응 정보 및 시각화 필드 부착
    detection_event["action"] = action
    detection_event["system_action"] = system_action
    detection_event["action_guide"] = action_guide
    detection_event["display"] = {
        "color": policy["dashboard_color"],
        "badge": policy["dashboard_badge"],
        "target_list": policy["dashboard_target"]
    }
    base_reason = detection_event.get("reason", "")
    detection_event["reason_full"] = f"{base_reason} | [대응가이드: {action_guide}]"

    return {
        "detection_event": detection_event,
        "block_event": block_event
    }