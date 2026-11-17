# 브루트포스 전용 대응 정책 및 대시보드 표시 매핑
BRUTEFORCE_ACTION_POLICY = {
    "LOW": {
        "action": "RECORD",
        "system_action": "일반 로그 저장",
        "action_guide": "별도 조치 없이 기록·관찰",
        "dashboard_color": "blue",
        "dashboard_badge": "🟦 관찰 (OBSERVE)",
        "dashboard_target": "일반 통계 / 이상 징후"
    },
    "MEDIUM": {
        "action": "ALERT",
        "system_action": "브루트포스 탐지 이벤트 저장 및 동일 IP/계정 누적 상태 갱신",
        "action_guide": "해당 IP의 실패 횟수와 시도 계정 수를 확인하고, 이후 반복 여부 감시",
        "dashboard_color": "yellow",
        "dashboard_badge": "🟨 경고 (WARNING)",
        "dashboard_target": "경고 목록"
    },
    "HIGH": {
        "action": "BLOCK_CANDIDATE",
        "system_action": "위험도와 탐지 근거를 이벤트에 저장하고 관리자 알림 후보 표시",
        "action_guide": "해당 IP와 계정 대상 실패 추이 확인. 로그인 제한이나 임시 차단을 검토하되 자동 차단은 하지 않음",
        "dashboard_color": "orange",
        "dashboard_badge": "🟧 알림 (ALERT)",
        "dashboard_target": "알림 목록"
    },
    "CRITICAL": {
        "action": "BLOCK",
        "system_action": "긴급 탐지 이벤트 및 알림 생성, 차단 후보 기록 후 일정 시간 차단 수행",
        "action_guide": "해당 계정·세션을 우선 조사하고, 필요하면 계정 잠금·세션 만료·IP 임시 차단 수행",
        "dashboard_color": "red",
        "dashboard_badge": "🟥 차단 (BLOCK)",
        "dashboard_target": "차단 목록"
    }
}


def apply_bruteforce_action(detection_event):
    """
    bruteforce.py에서 생성된 탐지 이벤트(detection_event)를 받아
    위험도에 맞는 대응 정책과 대시보드 시각화 정보를 부착하는 함수
    """
    if not detection_event:
        return None

    severity = detection_event.get("severity", "LOW")
    policy = BRUTEFORCE_ACTION_POLICY.get(severity, BRUTEFORCE_ACTION_POLICY["LOW"])

    # 액션 및 상세 대응 가이드 보완
    detection_event["action"] = policy["action"]
    detection_event["system_action"] = policy["system_action"]
    detection_event["action_guide"] = policy["action_guide"]

    # 대시보드 시각화 정보 추가
    detection_event["display"] = {
        "color": policy["dashboard_color"],
        "badge": policy["dashboard_badge"],
        "target_list": policy["dashboard_target"]
    }

    # 탐지 사유(reason)에 대응 가이드 통합
    base_reason = detection_event.get("reason", "")
    detection_event["reason_full"] = f"{base_reason} | [대응가이드: {policy['action_guide']}]"

    return detection_event