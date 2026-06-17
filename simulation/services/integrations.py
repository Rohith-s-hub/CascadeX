"""
Realtime Integration Engine
═══════════════════════════════════════════════════════════════
CascadeX external integration dispatcher for realtime event delivery.

Supported integrations
----------------------
- Slack webhook alerts
- Jira ticket creation
- PagerDuty incident trigger
- Generic webhook push

Design goals
------------
- Event-driven
- Near-realtime delivery
- Background dispatch worker
- Deduplication
- Retries
- Health checks
- Consistent event schema
- Safe configuration validation

Notes
-----
This module is a realtime backend prototype:
- events are queued in-memory
- delivery happens in a background worker thread
- suitable for single-process development / prototype use

For production-scale deployment, replace the in-memory queue with:
- Celery + Redis/RabbitMQ
or
- Kafka / Redis streams / SQS

But this version is fully functional for your current CascadeX system.
"""

import copy
import hashlib
import hmac
import json
import logging
import queue
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_integration_manager: Optional["IntegrationManager"] = None


# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════


class IntegrationConfig:
    """
    Runtime config for integration dispatcher.
    """

    HTTP_TIMEOUT = 10
    HTTP_CONNECT_TIMEOUT = 5
    MAX_RETRIES = 3
    QUEUE_MAXSIZE = 1000
    DEDUP_TTL_SECONDS = 120
    WORKER_SLEEP_SECONDS = 0.25
    MAX_EVENT_BODY_PREVIEW = 300
    JIRA_TIMEOUT = 15
    USER_AGENT = "CascadeX-IntegrationEngine/1.0"


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════


def _utc_ts() -> float:
    return time.time()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_json(data: Any) -> str:
    try:
        return json.dumps(data, sort_keys=True, default=str)
    except Exception:
        return str(data)


def _truncate(value: str, size: int) -> str:
    if len(value) <= size:
        return value
    return value[:size] + "..."


def _valid_http_url(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _build_requests_session() -> Session:
    """
    Shared hardened HTTP session with retries.
    """
    session = requests.Session()
    retry = Retry(
        total=2,
        read=2,
        connect=2,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT", "PATCH"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": IntegrationConfig.USER_AGENT,
    })
    return session


# ══════════════════════════════════════════════════════════════
# EVENT MODEL
# ══════════════════════════════════════════════════════════════


@dataclass
class IntegrationEvent:
    """
    Canonical event object delivered to all integrations.
    """

    event_id: str
    event_type: str
    severity: str
    title: str
    message: str
    source: str = "CascadeX"
    timestamp: str = field(default_factory=_now_iso)
    payload: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    dedup_key: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "source": self.source,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "tags": self.tags,
            "dedup_key": self.dedup_key,
        }

    @classmethod
    def from_alert(cls, alert: Dict[str, Any]) -> "IntegrationEvent":
        """
        Normalize arbitrary incoming dict into event structure.
        """
        event_type = str(alert.get("type", "generic_alert")).strip() or "generic_alert"
        severity = str(alert.get("severity", "info")).lower().strip()
        title = str(alert.get("title") or alert.get("type") or "CascadeX Alert").strip()
        message = str(alert.get("message", "No details")).strip()

        dedup_key = alert.get("dedup_key")
        if not dedup_key:
            dedup_seed = _safe_json({
                "type": event_type,
                "severity": severity,
                "title": title,
                "message": message,
                "target": alert.get("target"),
                "cve_id": alert.get("cve_id"),
            })
            dedup_key = hashlib.sha256(dedup_seed.encode()).hexdigest()

        payload = copy.deepcopy(alert)
        return cls(
            event_id=str(alert.get("event_id") or uuid.uuid4()),
            event_type=event_type,
            severity=severity,
            title=title,
            message=message,
            source=str(alert.get("source", "CascadeX")),
            timestamp=str(alert.get("timestamp") or _now_iso()),
            payload=payload,
            tags=list(alert.get("tags", [])),
            dedup_key=dedup_key,
        )


# ══════════════════════════════════════════════════════════════
# DELIVERY RESULT
# ══════════════════════════════════════════════════════════════


@dataclass
class DeliveryResult:
    integration: str
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None
    response_preview: Optional[str] = None
    external_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "integration": self.integration,
            "success": self.success,
            "status_code": self.status_code,
            "error": self.error,
            "response_preview": self.response_preview,
            "external_id": self.external_id,
        }


# ══════════════════════════════════════════════════════════════
# BASE INTEGRATION
# ══════════════════════════════════════════════════════════════


class BaseIntegration:
    """
    Base class for all outbound integrations.
    """

    integration_type = "base"

    def __init__(self, name: str):
        self.name = name
        self.session = _build_requests_session()

    def send_event(self, event: IntegrationEvent) -> DeliveryResult:
        raise NotImplementedError

    def test_connection(self) -> Dict[str, Any]:
        raise NotImplementedError

    def is_enabled(self) -> bool:
        return True


# ══════════════════════════════════════════════════════════════
# SLACK
# ══════════════════════════════════════════════════════════════


class SlackIntegration(BaseIntegration):
    """
    Slack webhook integration.
    """

    integration_type = "slack"

    def __init__(self, webhook_url: str, name: str = "slack"):
        super().__init__(name=name)
        self.webhook_url = webhook_url.strip()

        if not _valid_http_url(self.webhook_url):
            raise ValueError("Invalid Slack webhook URL")

        if "hooks.slack.com" not in self.webhook_url:
            logger.warning(
                "Configured Slack URL does not look like a standard Slack webhook"
            )

    def _severity_emoji(self, severity: str) -> str:
        return {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }.get(severity, "⚪")

    def send_event(self, event: IntegrationEvent) -> DeliveryResult:
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{self._severity_emoji(event.severity)} {event.title}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": event.message or "No details provided.",
                },
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"*Type:* {event.event_type}"},
                    {"type": "mrkdwn", "text": f"*Severity:* {event.severity.upper()}"},
                    {"type": "mrkdwn", "text": f"*Time:* {event.timestamp}"},
                ],
            },
        ]

        cves = event.payload.get("cves", [])
        if isinstance(cves, list) and cves:
            lines = []
            for cve in cves[:5]:
                if not isinstance(cve, dict):
                    continue
                lines.append(
                    f"• *{cve.get('cve_id', 'Unknown')}* "
                    f"(CVSS: {cve.get('cvss', cve.get('cvss_score', 'N/A'))}) "
                    f"— {_truncate(str(cve.get('description', '')), 100)}"
                )
            if lines:
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "*CVEs:*\n" + "\n".join(lines)},
                })

        body = {
            "text": f"{event.title}: {event.message}",
            "blocks": blocks,
        }

        try:
            response = self.session.post(
                self.webhook_url,
                json=body,
                timeout=(IntegrationConfig.HTTP_CONNECT_TIMEOUT, IntegrationConfig.HTTP_TIMEOUT),
            )
            ok = response.status_code == 200
            return DeliveryResult(
                integration=self.name,
                success=ok,
                status_code=response.status_code,
                error=None if ok else _truncate(response.text, 200),
                response_preview=_truncate(response.text, 200),
            )
        except Exception as exc:
            logger.error(f"Slack send failed: {exc}", exc_info=True)
            return DeliveryResult(
                integration=self.name,
                success=False,
                error=str(exc),
            )

    def test_connection(self) -> Dict[str, Any]:
        probe = IntegrationEvent(
            event_id=str(uuid.uuid4()),
            event_type="integration_test",
            severity="info",
            title="CascadeX Slack Test",
            message="Slack integration test from CascadeX.",
        )
        result = self.send_event(probe)
        return {
            "success": result.success,
            "integration": self.name,
            "details": result.to_dict(),
        }


# ══════════════════════════════════════════════════════════════
# JIRA
# ══════════════════════════════════════════════════════════════


class JiraIntegration(BaseIntegration):
    """
    Jira issue creation integration.
    """

    integration_type = "jira"

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str,
        issue_type: str = "Bug",
        name: str = "jira",
    ):
        super().__init__(name=name)
        self.base_url = base_url.rstrip("/")
        self.email = email.strip()
        self.api_token = api_token.strip()
        self.project_key = project_key.strip()
        self.issue_type = issue_type.strip() or "Bug"

        if not _valid_http_url(self.base_url):
            raise ValueError("Invalid Jira base URL")
        if not self.email:
            raise ValueError("Jira email is required")
        if not self.api_token:
            raise ValueError("Jira API token is required")
        if not self.project_key:
            raise ValueError("Jira project key is required")

        self.session.auth = (self.email, self.api_token)
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _priority_name(self, severity: str) -> str:
        return {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        }.get(severity, "Medium")

    def send_event(self, event: IntegrationEvent) -> DeliveryResult:
        payload = event.payload or {}
        cve_id = payload.get("cve_id") or payload.get("id") or "Security Finding"
        risk = payload.get("risk") or payload.get("risk_score") or "N/A"
        cvss = payload.get("cvss_score") or payload.get("cvss") or "N/A"
        attack_vector = payload.get("attack_vector") or "N/A"
        description = payload.get("description") or event.message

        explanation_lines = []
        for line in payload.get("risk_explanation", [])[:10]:
            explanation_lines.append(f"* {line}")

        jira_description = (
            f"h2. {cve_id}\n\n"
            f"*Severity:* {event.severity.upper()}\n"
            f"*Risk Score:* {risk}\n"
            f"*CVSS:* {cvss}\n"
            f"*Attack Vector:* {attack_vector}\n"
            f"*Event Type:* {event.event_type}\n"
            f"*Timestamp:* {event.timestamp}\n\n"
            f"h3. Description\n"
            f"{description}\n\n"
        )

        if explanation_lines:
            jira_description += "h3. Risk Explanation\n" + "\n".join(explanation_lines)

        issue_payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[{event.severity.upper()}] {event.title}",
                "description": jira_description,
                "issuetype": {"name": self.issue_type},
                "priority": {"name": self._priority_name(event.severity)},
                "labels": [
                    "security",
                    "cascadex",
                    event.event_type.lower().replace(" ", "_"),
                    event.severity.lower(),
                ],
            }
        }

        try:
            response = self.session.post(
                f"{self.base_url}/rest/api/2/issue",
                json=issue_payload,
                timeout=(IntegrationConfig.HTTP_CONNECT_TIMEOUT, IntegrationConfig.JIRA_TIMEOUT),
            )

            if response.status_code == 201:
                data = response.json()
                return DeliveryResult(
                    integration=self.name,
                    success=True,
                    status_code=201,
                    external_id=data.get("key"),
                    response_preview=_truncate(response.text, 200),
                )

            return DeliveryResult(
                integration=self.name,
                success=False,
                status_code=response.status_code,
                error=_truncate(response.text, 300),
                response_preview=_truncate(response.text, 200),
            )

        except Exception as exc:
            logger.error(f"Jira ticket creation failed: {exc}", exc_info=True)
            return DeliveryResult(
                integration=self.name,
                success=False,
                error=str(exc),
            )

    def test_connection(self) -> Dict[str, Any]:
        try:
            response = self.session.get(
                f"{self.base_url}/rest/api/2/myself",
                timeout=(IntegrationConfig.HTTP_CONNECT_TIMEOUT, IntegrationConfig.HTTP_TIMEOUT),
            )
            ok = response.status_code == 200
            return {
                "success": ok,
                "integration": self.name,
                "status_code": response.status_code,
                "response_preview": _truncate(response.text, 200),
            }
        except Exception as exc:
            return {
                "success": False,
                "integration": self.name,
                "error": str(exc),
            }


# ══════════════════════════════════════════════════════════════
# PAGERDUTY
# ══════════════════════════════════════════════════════════════


class PagerDutyIntegration(BaseIntegration):
    """
    PagerDuty Events API integration.
    """

    integration_type = "pagerduty"

    def __init__(self, integration_key: str, name: str = "pagerduty"):
        super().__init__(name=name)
        self.integration_key = integration_key.strip()
        self.api_url = "https://events.pagerduty.com/v2/enqueue"

        if not self.integration_key or len(self.integration_key) < 16:
            raise ValueError("Invalid PagerDuty integration key")

    def send_event(self, event: IntegrationEvent) -> DeliveryResult:
        severity_map = {
            "critical": "critical",
            "high": "error",
            "medium": "warning",
            "low": "info",
            "info": "info",
        }

        payload = {
            "routing_key": self.integration_key,
            "event_action": "trigger",
            "dedup_key": event.dedup_key,
            "payload": {
                "summary": event.title,
                "severity": severity_map.get(event.severity, "info"),
                "source": event.source,
                "component": "CascadeX",
                "group": event.event_type,
                "class": "security",
                "custom_details": event.to_dict(),
            },
        }

        try:
            response = self.session.post(
                self.api_url,
                json=payload,
                timeout=(IntegrationConfig.HTTP_CONNECT_TIMEOUT, IntegrationConfig.HTTP_TIMEOUT),
            )

            ok = response.status_code == 202
            data = {}
            try:
                data = response.json()
            except Exception:
                data = {}

            return DeliveryResult(
                integration=self.name,
                success=ok,
                status_code=response.status_code,
                error=None if ok else _truncate(response.text, 200),
                response_preview=_truncate(response.text, 200),
                external_id=data.get("dedup_key"),
            )
        except Exception as exc:
            logger.error(f"PagerDuty send failed: {exc}", exc_info=True)
            return DeliveryResult(
                integration=self.name,
                success=False,
                error=str(exc),
            )

    def test_connection(self) -> Dict[str, Any]:
        probe = IntegrationEvent(
            event_id=str(uuid.uuid4()),
            event_type="integration_test",
            severity="info",
            title="CascadeX PagerDuty Test",
            message="PagerDuty integration test from CascadeX.",
        )
        result = self.send_event(probe)
        return {
            "success": result.success,
            "integration": self.name,
            "details": result.to_dict(),
        }


# ══════════════════════════════════════════════════════════════
# GENERIC WEBHOOK
# ══════════════════════════════════════════════════════════════


class WebhookIntegration(BaseIntegration):
    """
    Generic signed webhook integration.
    """

    integration_type = "webhook"

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        secret: Optional[str] = None,
        method: str = "POST",
        name: str = "webhook",
    ):
        super().__init__(name=name)
        self.url = url.strip()
        self.secret = secret.strip() if secret else None
        self.method = method.upper().strip()
        self.base_headers = headers.copy() if headers else {}
        self.base_headers.setdefault("Content-Type", "application/json")

        if self.method not in ("POST",):
            raise ValueError("Only POST method is supported in this prototype")

        if not _valid_http_url(self.url):
            raise ValueError("Invalid webhook URL")

    def _build_headers(self, body: str) -> Dict[str, str]:
        headers = self.base_headers.copy()
        if self.secret:
            signature = hmac.new(
                self.secret.encode("utf-8"),
                body.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            headers["X-CascadeX-Signature"] = signature
            headers["X-CascadeX-Signature-Alg"] = "sha256"
        return headers

    def send_event(self, event: IntegrationEvent) -> DeliveryResult:
        body = _safe_json(event.to_dict())
        headers = self._build_headers(body)

        try:
            response = self.session.post(
                self.url,
                data=body,
                headers=headers,
                timeout=(IntegrationConfig.HTTP_CONNECT_TIMEOUT, IntegrationConfig.HTTP_TIMEOUT),
            )

            ok = response.status_code in (200, 201, 202, 204)
            return DeliveryResult(
                integration=self.name,
                success=ok,
                status_code=response.status_code,
                error=None if ok else _truncate(response.text, 300),
                response_preview=_truncate(response.text, 200),
            )
        except Exception as exc:
            logger.error(f"Webhook send failed: {exc}", exc_info=True)
            return DeliveryResult(
                integration=self.name,
                success=False,
                error=str(exc),
            )

    def test_connection(self) -> Dict[str, Any]:
        probe = IntegrationEvent(
            event_id=str(uuid.uuid4()),
            event_type="integration_test",
            severity="info",
            title="CascadeX Webhook Test",
            message="Webhook integration test from CascadeX.",
        )
        result = self.send_event(probe)
        return {
            "success": result.success,
            "integration": self.name,
            "details": result.to_dict(),
        }


# ══════════════════════════════════════════════════════════════
# IN-MEMORY REALTIME DISPATCHER
# ══════════════════════════════════════════════════════════════


class IntegrationManager:
    """
    Central realtime integration manager.

    Responsibilities
    ----------------
    - register integrations
    - accept events
    - deduplicate events
    - queue for background dispatch
    - deliver to all configured integrations
    - expose delivery/test/health helpers

    Realtime behavior
    -----------------
    This manager runs a background worker thread.
    When an event is published, it is placed into an in-memory queue.
    The worker consumes it and sends it to all configured integrations
    immediately, without blocking the main scan flow.
    """

    def __init__(self):
        self.integrations: Dict[str, BaseIntegration] = {}
        self.event_queue: "queue.Queue[IntegrationEvent]" = queue.Queue(
            maxsize=IntegrationConfig.QUEUE_MAXSIZE
        )
        self._recent_dedup: Dict[str, float] = {}
        self._recent_results: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

    # ──────────────────────────────────────────────────────────
    # LIFECYCLE
    # ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Start background event dispatcher.
        Safe to call multiple times.
        """
        with self._lock:
            if self._running:
                return
            self._running = True
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="cascadex-integration-worker",
                daemon=True,
            )
            self._worker_thread.start()
            logger.info("IntegrationManager worker started")

    def stop(self, timeout: float = 2.0) -> None:
        """
        Stop background worker.
        """
        with self._lock:
            self._running = False

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
        logger.info("IntegrationManager worker stopped")

    def _worker_loop(self) -> None:
        """
        Background dispatch loop.
        """
        while self._running:
            try:
                event = self.event_queue.get(timeout=0.5)
            except queue.Empty:
                self._cleanup_dedup_cache()
                continue

            try:
                self._dispatch_event_now(event)
            except Exception as exc:
                logger.error(f"Event dispatch failed: {exc}", exc_info=True)
            finally:
                self.event_queue.task_done()

            time.sleep(IntegrationConfig.WORKER_SLEEP_SECONDS)

    # ──────────────────────────────────────────────────────────
    # CONFIGURATION
    # ──────────────────────────────────────────────────────────

    def configure_slack(self, webhook_url: str, name: str = "slack") -> Dict[str, Any]:
        integration = SlackIntegration(webhook_url=webhook_url, name=name)
        self.integrations[name] = integration
        logger.info(f"Slack integration configured: {name}")
        return {"success": True, "name": name, "type": "slack"}

    def configure_jira(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str,
        issue_type: str = "Bug",
        name: str = "jira",
    ) -> Dict[str, Any]:
        integration = JiraIntegration(
            base_url=base_url,
            email=email,
            api_token=api_token,
            project_key=project_key,
            issue_type=issue_type,
            name=name,
        )
        self.integrations[name] = integration
        logger.info(f"Jira integration configured: {name}")
        return {"success": True, "name": name, "type": "jira"}

    def configure_pagerduty(
        self,
        integration_key: str,
        name: str = "pagerduty",
    ) -> Dict[str, Any]:
        integration = PagerDutyIntegration(
            integration_key=integration_key,
            name=name,
        )
        self.integrations[name] = integration
        logger.info(f"PagerDuty integration configured: {name}")
        return {"success": True, "name": name, "type": "pagerduty"}

    def configure_webhook(
        self,
        name: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        integration = WebhookIntegration(
            url=url,
            headers=headers,
            secret=secret,
            name=name,
        )
        self.integrations[name] = integration
        logger.info(f"Webhook integration configured: {name}")
        return {"success": True, "name": name, "type": "webhook"}

    def remove_integration(self, name: str) -> Dict[str, Any]:
        if name in self.integrations:
            del self.integrations[name]
            return {"success": True, "removed": name}
        return {"success": False, "error": "Integration not found"}

    def list_integrations(self) -> List[Dict[str, Any]]:
        items = []
        for name, integration in self.integrations.items():
            items.append({
                "name": name,
                "type": integration.integration_type,
                "enabled": integration.is_enabled(),
            })
        return items

    # ──────────────────────────────────────────────────────────
    # EVENT PUBLISHING
    # ──────────────────────────────────────────────────────────

    def publish_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize and enqueue an alert for realtime delivery.
        """
        event = IntegrationEvent.from_alert(alert)
        return self.publish_event(event)

    def publish_event(self, event: IntegrationEvent) -> Dict[str, Any]:
        """
        Queue an event for background dispatch.
        """
        self.start()

        if self._is_duplicate(event):
            logger.info(
                f"Skipping duplicate integration event: {event.event_type} {event.dedup_key}"
            )
            return {
                "success": True,
                "queued": False,
                "reason": "duplicate_suppressed",
                "event_id": event.event_id,
                "dedup_key": event.dedup_key,
            }

        try:
            self.event_queue.put_nowait(event)
            logger.info(
                f"Queued integration event {event.event_id} "
                f"type={event.event_type} severity={event.severity}"
            )
            return {
                "success": True,
                "queued": True,
                "event_id": event.event_id,
                "queue_size": self.event_queue.qsize(),
            }
        except queue.Full:
            logger.error("Integration event queue is full")
            return {
                "success": False,
                "queued": False,
                "error": "event_queue_full",
            }

    def send_alert_now(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Immediate synchronous dispatch.
        Useful for testing or forced delivery.
        """
        event = IntegrationEvent.from_alert(alert)
        return self._dispatch_event_now(event)

    # ──────────────────────────────────────────────────────────
    # DISPATCH
    # ──────────────────────────────────────────────────────────

    def _dispatch_event_now(self, event: IntegrationEvent) -> Dict[str, Any]:
        """
        Fan out event to all registered integrations.
        """
        results: List[DeliveryResult] = []

        if not self.integrations:
            logger.warning("No integrations configured; event dropped")
            result = {
                "success": False,
                "event_id": event.event_id,
                "error": "no_integrations_configured",
                "results": [],
            }
            self._store_recent_result(result)
            return result

        for name, integration in list(self.integrations.items()):
            try:
                delivery = integration.send_event(event)
                results.append(delivery)
            except Exception as exc:
                logger.error(
                    f"Integration {name} failed unexpectedly: {exc}",
                    exc_info=True,
                )
                results.append(
                    DeliveryResult(
                        integration=name,
                        success=False,
                        error=str(exc),
                    )
                )

        overall_success = any(r.success for r in results)

        result = {
            "success": overall_success,
            "event_id": event.event_id,
            "event_type": event.event_type,
            "severity": event.severity,
            "results": [r.to_dict() for r in results],
        }
        self._store_recent_result(result)
        return result

    # ──────────────────────────────────────────────────────────
    # DEDUP
    # ──────────────────────────────────────────────────────────

    def _is_duplicate(self, event: IntegrationEvent) -> bool:
        """
        Suppress duplicate events during TTL window.
        """
        now = _utc_ts()
        self._cleanup_dedup_cache()

        if not event.dedup_key:
            return False

        last_seen = self._recent_dedup.get(event.dedup_key)
        if last_seen and (now - last_seen) < IntegrationConfig.DEDUP_TTL_SECONDS:
            return True

        self._recent_dedup[event.dedup_key] = now
        return False

    def _cleanup_dedup_cache(self) -> None:
        """
        Remove expired dedup keys.
        """
        now = _utc_ts()
        expired = [
            key for key, ts in self._recent_dedup.items()
            if (now - ts) >= IntegrationConfig.DEDUP_TTL_SECONDS
        ]
        for key in expired:
            self._recent_dedup.pop(key, None)

    # ──────────────────────────────────────────────────────────
    # OBSERVABILITY
    # ──────────────────────────────────────────────────────────

    def _store_recent_result(self, result: Dict[str, Any]) -> None:
        with self._lock:
            self._recent_results.append(result)
            self._recent_results = self._recent_results[-100:]

    def get_recent_results(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._recent_results)

    def get_status(self) -> Dict[str, Any]:
        return {
            "running": self._running,
            "queue_size": self.event_queue.qsize(),
            "integrations_configured": len(self.integrations),
            "integrations": self.list_integrations(),
            "dedup_cache_size": len(self._recent_dedup),
        }

    def test_all_integrations(self) -> Dict[str, Any]:
        results = []
        for name, integration in self.integrations.items():
            try:
                results.append(integration.test_connection())
            except Exception as exc:
                results.append({
                    "success": False,
                    "integration": name,
                    "error": str(exc),
                })
        return {
            "success": all(r.get("success") for r in results) if results else False,
            "results": results,
        }

    # ──────────────────────────────────────────────────────────
    # CASCADEX-SPECIFIC EVENT HELPERS
    # ──────────────────────────────────────────────────────────

    def notify_scan_completed(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Publish scan completion event.
        """
        severity = "info"
        vuln_count = int(scan_result.get("vuln_count", 0) or 0)
        if vuln_count >= 10:
            severity = "high"
        elif vuln_count >= 1:
            severity = "medium"

        alert = {
            "type": "scan_completed",
            "severity": severity,
            "title": f"Scan Complete: {scan_result.get('scan_type', 'unknown')}",
            "message": (
                f"Target {scan_result.get('target', 'unknown')} scanned. "
                f"Hosts: {scan_result.get('host_count', 0)}, "
                f"Services: {scan_result.get('total_services', 0)}, "
                f"Vulnerabilities: {vuln_count}"
            ),
            "target": scan_result.get("target"),
            "scan_id": scan_result.get("scan_id"),
            "scan_type": scan_result.get("scan_type"),
            "host_count": scan_result.get("host_count", 0),
            "service_count": scan_result.get("total_services", 0),
            "vuln_count": vuln_count,
            "duration": scan_result.get("duration", 0),
            "timestamp": scan_result.get("timestamp", _now_iso()),
            "payload": scan_result,
            "tags": ["scan", "active_scan", "cascadex"],
            "dedup_key": f"scan:{scan_result.get('scan_id') or scan_result.get('target')}:{scan_result.get('scan_type')}",
        }
        return self.publish_alert(alert)

    def notify_critical_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Publish critical vulnerability event.
        """
        alert = {
            "type": "critical_vulnerability",
            "severity": "critical",
            "title": f"Critical Vulnerability: {vulnerability.get('cve_id', 'Unknown')}",
            "message": vulnerability.get("description", "Critical vulnerability detected."),
            "cve_id": vulnerability.get("cve_id"),
            "cvss_score": vulnerability.get("cvss_score"),
            "risk": vulnerability.get("risk"),
            "attack_vector": vulnerability.get("attack_vector"),
            "payload": vulnerability,
            "tags": ["vulnerability", "critical", "cve", "cascadex"],
            "dedup_key": f"critical_cve:{vulnerability.get('cve_id')}",
        }
        return self.publish_alert(alert)

    def notify_risk_changed(
        self,
        previous_health: Optional[int],
        current_health: Optional[int],
        snapshot: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Publish risk posture change event.
        """
        if previous_health is None or current_health is None:
            severity = "info"
        elif current_health < previous_health:
            severity = "high"
        elif current_health > previous_health:
            severity = "info"
        else:
            severity = "low"

        alert = {
            "type": "risk_posture_changed",
            "severity": severity,
            "title": "Risk Posture Updated",
            "message": (
                f"System health changed from {previous_health} to {current_health}."
            ),
            "previous_health": previous_health,
            "current_health": current_health,
            "payload": snapshot or {},
            "tags": ["risk", "trending", "snapshot", "cascadex"],
            "dedup_key": f"risk_change:{previous_health}:{current_health}",
        }
        return self.publish_alert(alert)


def get_integration_manager() -> IntegrationManager:
    """Return a shared process-local integration manager."""
    global _integration_manager
    if _integration_manager is None:
        _integration_manager = IntegrationManager()
    return _integration_manager
