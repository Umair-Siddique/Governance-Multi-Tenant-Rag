"""
Audit log read API — admin-only.
Returns immutable tenant-scoped governance events with pagination and filters.

Endpoints:
  GET /audit-logs         — paginated list, newest first
  GET /audit-logs/stats   — event counts grouped by type/category
  GET /audit-logs/health  — test write+read path, surfaces the exact error
"""
import uuid as _uuid
from collections import Counter
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, current_app

from utils.auth_helpers import canonical_tenant_id, require_role
from utils.supabase_retry import execute_with_retry

audit_logs_bp = Blueprint("audit_logs", __name__)

_VALID_CATEGORIES = frozenset({"content", "ai", "admin"})
_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200

_SELECT_COLS = (
    "id, event_category, event_type, actor_id, actor_email, "
    "target_id, target_type, metadata, ip_address, created_at"
)


def _parse_int(value, default: int, lo: int = 1, hi: int = 10_000) -> int:
    try:
        return max(lo, min(int(value), hi))
    except (TypeError, ValueError):
        return default


@audit_logs_bp.route("/audit-logs/health", methods=["GET"])
@require_role("admin")
def audit_log_health(**kwargs):
    """
    Diagnostic endpoint — tests the full write → read → delete cycle.
    Call this when audit_logs appear empty to see the exact error.

    Returns a JSON object with:
      table_exists    — whether a SELECT on audit_logs succeeded
      write_ok        — whether an INSERT succeeded
      read_ok         — whether the inserted row was found
      insert_error    — exact exception message if insert failed (null = success)
      read_error      — exact exception message if select failed (null = success)
      tenant_id_used  — the tenant_id that was passed to the insert
    """
    tenant_id = canonical_tenant_id(kwargs["tenant_id"])
    if not tenant_id:
        return jsonify({"error": "Invalid tenant context"}), 403

    current_user = kwargs["current_user"]

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    test_id = str(_uuid.uuid4())
    test_row = {
        "id": test_id,
        "tenant_id": tenant_id,
        "event_category": "admin",
        "event_type": "_health_check",
        "actor_id": str(current_user.get("id") or ""),
        "actor_email": current_user.get("email"),
        "metadata": {"test": True},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # Step 1 — try SELECT first (proves table exists)
    table_exists = False
    read_error = None
    try:
        supabase.table("audit_logs").select("id").eq("tenant_id", tenant_id).limit(1).execute()
        table_exists = True
    except Exception as e:
        read_error = str(e)

    # Step 2 — try INSERT
    write_ok = False
    insert_error = None
    try:
        supabase.table("audit_logs").insert(test_row).execute()
        write_ok = True
    except Exception as e:
        insert_error = str(e)

    # Step 3 — read the test row back
    read_ok = False
    if write_ok:
        try:
            r = supabase.table("audit_logs").select("id").eq("id", test_id).execute()
            read_ok = bool(r.data)
        except Exception as e:
            read_error = str(e)

    # Step 4 — clean up the test row
    if write_ok:
        try:
            supabase.table("audit_logs").delete().eq("id", test_id).execute()
        except Exception:
            pass

    status = 200 if (table_exists and write_ok and read_ok) else 500
    return jsonify({
        "healthy": table_exists and write_ok and read_ok,
        "table_exists": table_exists,
        "write_ok": write_ok,
        "read_ok": read_ok,
        "insert_error": insert_error,
        "read_error": read_error,
        "tenant_id_used": tenant_id,
    }), status


@audit_logs_bp.route("/audit-logs", methods=["GET"])
@require_role("admin")
def list_audit_logs(**kwargs):
    """
    List audit logs for the tenant (admin only), newest first.

    Returns events for the whole tenant (all roles): uploads and approvals by
    editors/reviewers appear alongside admin events. Omit query param
    ``event_category`` to include content, ai, and admin categories.

    Query params:
      event_category  — 'content' | 'ai' | 'admin'
      event_type      — exact match (e.g. 'document.uploaded')
      actor_id        — UUID of the user who performed the action
      target_id       — UUID of the affected resource
      from_date       — ISO 8601 lower bound (inclusive)
      to_date         — ISO 8601 upper bound (inclusive)
      limit           — default 50, max 200
      page            — 1-based page index, default 1
    """
    tenant_id = canonical_tenant_id(kwargs["tenant_id"])
    if not tenant_id:
        return jsonify({"error": "Invalid tenant context"}), 403

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    event_category = (request.args.get("event_category") or "").strip().lower() or None
    event_type = (request.args.get("event_type") or "").strip() or None
    actor_id = (request.args.get("actor_id") or "").strip() or None
    target_id = (request.args.get("target_id") or "").strip() or None
    from_date = (request.args.get("from_date") or "").strip() or None
    to_date = (request.args.get("to_date") or "").strip() or None

    if event_category and event_category not in _VALID_CATEGORIES:
        return jsonify(
            {"error": f"event_category must be one of: {sorted(_VALID_CATEGORIES)}"}
        ), 400

    lim = _parse_int(request.args.get("limit"), _DEFAULT_LIMIT, 1, _MAX_LIMIT)
    pg = _parse_int(request.args.get("page"), 1, 1, 100_000)

    start = (pg - 1) * lim
    end = start + lim  # fetch lim+1 rows so we can compute has_more

    try:
        q = (
            supabase.table("audit_logs")
            .select(_SELECT_COLS)
            .eq("tenant_id", tenant_id)
            .order("created_at", desc=True)
        )
        if event_category:
            q = q.eq("event_category", event_category)
        if event_type:
            q = q.eq("event_type", event_type)
        if actor_id:
            q = q.eq("actor_id", actor_id)
        if target_id:
            q = q.eq("target_id", target_id)
        if from_date:
            q = q.gte("created_at", from_date)
        if to_date:
            q = q.lte("created_at", to_date)

        result = execute_with_retry(lambda: q.range(start, end).execute())
    except Exception as e:
        current_app.logger.exception("list_audit_logs failed")
        return jsonify({"error": f"Failed to fetch audit logs: {e}"}), 500

    rows = result.data or []
    has_more = len(rows) > lim
    if has_more:
        rows = rows[:lim]

    return jsonify({
        "audit_logs": rows,
        "page": pg,
        "limit": lim,
        "has_more": has_more,
        "filters": {
            "event_category": event_category,
            "event_type": event_type,
            "actor_id": actor_id,
            "target_id": target_id,
            "from_date": from_date,
            "to_date": to_date,
        },
    }), 200


@audit_logs_bp.route("/audit-logs/stats", methods=["GET"])
@require_role("admin")
def audit_log_stats(**kwargs):
    """
    Return event counts grouped by category and event_type.

    Query params (all optional):
      event_category — narrow to one category
      from_date      — ISO 8601 lower bound
      to_date        — ISO 8601 upper bound
    """
    tenant_id = canonical_tenant_id(kwargs["tenant_id"])
    if not tenant_id:
        return jsonify({"error": "Invalid tenant context"}), 403

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    event_category = (request.args.get("event_category") or "").strip().lower() or None
    from_date = (request.args.get("from_date") or "").strip() or None
    to_date = (request.args.get("to_date") or "").strip() or None

    if event_category and event_category not in _VALID_CATEGORIES:
        return jsonify(
            {"error": f"event_category must be one of: {sorted(_VALID_CATEGORIES)}"}
        ), 400

    try:
        q = (
            supabase.table("audit_logs")
            .select("event_category, event_type")
            .eq("tenant_id", tenant_id)
        )
        if event_category:
            q = q.eq("event_category", event_category)
        if from_date:
            q = q.gte("created_at", from_date)
        if to_date:
            q = q.lte("created_at", to_date)

        result = execute_with_retry(lambda: q.execute())
    except Exception as e:
        current_app.logger.exception("audit_log_stats failed")
        return jsonify({"error": f"Failed to fetch audit stats: {e}"}), 500

    rows = result.data or []
    by_category = dict(Counter(r["event_category"] for r in rows))
    by_event_type = dict(Counter(r["event_type"] for r in rows))

    return jsonify({
        "total": len(rows),
        "by_category": by_category,
        "by_event_type": by_event_type,
        "filters": {
            "event_category": event_category,
            "from_date": from_date,
            "to_date": to_date,
        },
    }), 200
