from datetime import datetime, timedelta

# SQLi 설정값
TEMPORARY_BLOCK_MINUTES = 30  # Critical 자동 차단 시 기본 차단 시간 (30분)

# 4단계 위험도별 SQLi 대응 정책 정의
SQLI_RESPONSE_POLICY = {
    "LOW": {
        "action": "RECORD",
        "system_action": "일반 탐지 로그 기록 및 추세 관찰",
        "action_guide": "단발성 의심 문자열로 별도 차단 없이 로그 기록 및 추세 관찰",
        "dashboard_color": "blue",
        "dashboard_badge": "🟦 관찰 (LOW)",
        "dashboard_target": "일반 통계 / 이상 징후"
    },
    "MEDIUM": {
        "action": "ALERT",
        "system_action": "SQLi 탐지 이벤트 저장 및 동일 IP 반복 여부 추적",
        "action_guide": "알림 생성 및 원본 로그(query_string, request_body)의 SQL 구문 여부 확인",
        "dashboard_color": "yellow",
        "dashboard_badge": "🟨 경고 (MEDIUM)",
        "dashboard_target": "경고 목록"
    },
    "HIGH": {
        "action": "MANUAL_REVIEW",
        "system_action": "고위험 SQLi 이벤트 및 가중치 근거 저장, 관리자 즉시 검토 알림",
        "action_guide": "즉시 조사 착수, 동일 IP 반복·경로 확산 여부 확인 및 WAF/입력값 검증(Prepared Statement) 점검",
        "dashboard_color": "orange",
        "dashboard_badge": "🟧 검토 (HIGH)",
        "dashboard_target": "알림 목록"
    },
    "CRITICAL": {
        "action": "BLOCK",
        "system_action": "긴급 SQLi 이벤트 생성 및 차단 후보 기록, IP 30분 임시 차단 실행",
        "action_guide": "IP 임시 차단 수행 후 인증 우회 세션 만료, DB 오류 노출 및 데이터 유출·변조 영향 긴급 확인",
        "dashboard_color": "red",
        "dashboard_badge": "🟥 차단 (CRITICAL)",
        "dashboard_target": "차단 목록"
    }
}

# 차단된 IP 목록 관리용 (시연 및 상태 확인용)
blocked_ips = {}


def process_sqli_action(detection_event):
    """
    SQLi 탐지기에서 반환된 detection_event를 받아
    위험도별 대응 가이드, 대시보드 표기 정보, CRITICAL 시 임시 차단 정보를 추가합니다.
    """
    if not detection_event:
        return None

    severity = detection_event.get("severity", "LOW")
    policy = SQLI_RESPONSE_POLICY.get(severity, SQLI_RESPONSE_POLICY["LOW"])

    # 1. 대응 정책 필드 부착
    detection_event["action"] = policy["action"]
    detection_event["system_action"] = policy["system_action"]
    detection_event["action_guide"] = policy["action_guide"]
    detection_event["display"] = {
        "color": policy["dashboard_color"],
        "badge": policy["dashboard_badge"],
        "target_list": policy["dashboard_target"]
    }

    # 2. CRITICAL 등급일 경우 30분 임시 차단 처리 및 차단 만료 시각 기록
    if severity == "CRITICAL":
        client_ip = detection_event.get("client_ip")
        detected_at_str = detection_event.get("detected_at")
        try:
            now = datetime.fromisoformat(detected_at_str)
        except (ValueError, TypeError):
            now = datetime.now()

        blocked_until = (now + timedelta(minutes=TEMPORARY_BLOCK_MINUTES)).isoformat()
        blocked_ips[client_ip] = blocked_until

        detection_event["is_blocked"] = True
        detection_event["blocked_until"] = blocked_until
    else:
        detection_event["is_blocked"] = False
        detection_event["blocked_until"] = None

    # 3. 최종 사유(reason)에 대응 가이드 문구 결합
    base_reason = detection_event.get("reason", "")
    detection_event["reason_full"] = f"{base_reason} | [대응가이드: {policy['action_guide']}]"

    return detection_event