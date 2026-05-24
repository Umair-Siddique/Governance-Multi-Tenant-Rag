"""
Audit log utility — fire-and-forget helper.
Never raises; a log failure must never block the calling request.
"""
import logging
import sys
import uuid
from datetime import date, datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from utils.auth_helpers import canonical_tenant_id

logger = logging.getLogger(__name__)

_VALID_CATEGORIES = frozenset({"content", "ai", "admin"})


def _json_safe_metadata(value: Any) -> Any:
    """
    Recursively coerce values so PostgREST JSON serialization never fails.
    Supabase rows often return UUID (and occasionally datetime) objects; those
    break the HTTP JSON encoder if placed raw inside metadata.
    """
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe_metadata(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe_metadata(v) for v in value]
    return str(value)


def log_audit_event(
    supabase,
    *,
    tenant_id: str,
    event_category: str,
    event_type: str,
    actor_id: Optional[str] = None,
    actor_email: Optional[str] = None,
    actor_role: Optional[str] = None,
    target_id: Optional[str] = None,
    target_type: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Append one row to audit_logs. Call this after the main action succeeds.

    event_category: 'content' | 'ai' | 'admin'
    event_type examples:
      content → document.uploaded, document.deleted, document.batch_approved,
                document.batch_rejected, document.batch_submitted_for_review,
                document.published_to_pinecone, document.status_changed
      ai      → ai.query_asked, ai.temp_file_uploaded
      admin   → admin.user_invited, admin.invitation_revoked, admin.user_registered

    actor_role: role of the user who performed the action ('admin' | 'editor' | 'reviewer' | 'user').
                Stored inside the metadata JSON so admins can filter/group by role without a schema change.
    """
    tid = canonical_tenant_id(tenant_id)
    if not supabase or not tid:
        print(
            f"[AUDIT SKIP] {event_category}/{event_type} — supabase={bool(supabase)} tenant_id={tenant_id!r}",
            file=sys.stderr, flush=True,
        )
        return
    if event_category not in _VALID_CATEGORIES:
        print(
            f"[AUDIT SKIP] unknown event_category {event_category!r}",
            file=sys.stderr, flush=True,
        )
        return

    safe_meta: Dict[str, Any] = _json_safe_metadata(metadata or {})
    if not isinstance(safe_meta, dict):
        safe_meta = {"_raw": safe_meta}
    if actor_role:
        safe_meta["actor_role"] = actor_role

    row = {
        "id": str(uuid.uuid4()),
        "tenant_id": tid,
        "event_category": event_category,
        "event_type": event_type,
        "actor_id": str(actor_id) if actor_id else None,
        "actor_email": actor_email,
        "target_id": str(target_id) if target_id else None,
        "target_type": target_type,
        "metadata": safe_meta,
        "ip_address": ip_address,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        supabase.table("audit_logs").insert(row).execute()
        print(
            f"[AUDIT OK] {event_category}/{event_type} tenant={tid} actor={actor_id}({actor_role or '?'}) target={target_id}",
            file=sys.stderr, flush=True,
        )
    except Exception as exc:
        # Always print to stderr so the error is visible in Render / local console
        # even when Python logging is not configured.
        print(
            f"[AUDIT WRITE FAILED] {event_category}/{event_type} tenant={tid}: {exc}",
            file=sys.stderr, flush=True,
        )
        logger.warning(
            "audit: write failed [%s/%s] tenant=%s: %s",
            event_category, event_type, tid, exc,
        )
