"""
Tenant-scoped chat history: conversations with titles and messages.
``chat_scope`` splits history: ``admin`` (tenant role admin only) vs ``member``
(editor / reviewer / user). The Flask API always filters by JWT tenant and scope.
"""
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request, current_app

from utils.auth_helpers import require_auth
from utils.supabase_retry import execute_with_retry

chats_bp = Blueprint("chats", __name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)

_ALLOWED_MESSAGE_ROLES = frozenset({"user", "assistant", "system"})
_MAX_TITLE_LEN = 500
_MAX_MESSAGE_CHARS = 200_000
_DEFAULT_MESSAGE_PAGE = 100


def _resolve_user_role(current_user: Dict[str, Any]) -> str:
    um = current_user.get("user_metadata") or {}
    am = current_user.get("app_metadata") or {}
    role = (um.get("role") or am.get("role") or "user")
    return str(role).strip().lower() or "user"


def _chat_scope_for_role(user_role: str) -> str:
    """Admin workspace vs member (non-admin) workspace."""
    return "admin" if user_role == "admin" else "member"


def _valid_uuid(s: str) -> bool:
    return bool(s and _UUID_RE.match(s.strip()))


@chats_bp.route("/chats/conversations", methods=["GET"])
@require_auth
def list_conversations(**kwargs):
    """
    List conversations for the current tenant and the caller's scope (admin vs member).

    Query: ``limit`` (optional, default 50, max 100).
    """
    tenant_id = kwargs["tenant_id"]
    user_role = _resolve_user_role(kwargs["current_user"])
    scope = _chat_scope_for_role(user_role)

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    limit = request.args.get("limit", "50")
    try:
        lim = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        lim = 50

    try:
        result = execute_with_retry(
            lambda: supabase.table("chat_conversations")
            .select("id, tenant_id, title, chat_scope, created_by, created_at, updated_at")
            .eq("tenant_id", tenant_id)
            .eq("chat_scope", scope)
            .order("updated_at", desc=True)
            .limit(lim)
            .execute()
        )
    except Exception as e:
        current_app.logger.exception("list_conversations failed")
        return jsonify({"error": f"Failed to list conversations: {e}"}), 500

    return jsonify({"conversations": result.data or [], "chat_scope": scope}), 200


@chats_bp.route("/chats/conversations/titles", methods=["GET"])
@require_auth
def list_conversation_titles(**kwargs):
    """
    List conversation titles for the current tenant and the caller's scope (admin vs member).

    Query:
      - limit (optional, default 10, max 100)
      - page  (optional, default 1) 1-based page index
    """
    tenant_id = kwargs["tenant_id"]
    user_role = _resolve_user_role(kwargs["current_user"])
    scope = _chat_scope_for_role(user_role)

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    limit = request.args.get("limit", "10")
    try:
        lim = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        lim = 10

    page = request.args.get("page", "1")
    try:
        pg = max(1, int(page))
    except (TypeError, ValueError):
        pg = 1

    start = (pg - 1) * lim
    end = start + lim  # fetch lim+1 to compute has_more

    try:
        result = execute_with_retry(
            lambda: supabase.table("chat_conversations")
            .select("id, title, updated_at, created_at")
            .eq("tenant_id", tenant_id)
            .eq("chat_scope", scope)
            .order("updated_at", desc=True)
            .range(start, end)
            .execute()
        )
    except Exception as e:
        current_app.logger.exception("list_conversation_titles failed")
        return jsonify({"error": f"Failed to list conversation titles: {e}"}), 500

    rows = result.data or []
    has_more = len(rows) > lim
    if has_more:
        rows = rows[:lim]

    return (
        jsonify(
            {
                "chat_scope": scope,
                "page": pg,
                "limit": lim,
                "has_more": has_more,
                "titles": rows,
            }
        ),
        200,
    )


@chats_bp.route("/chats/conversations", methods=["POST"])
@require_auth
def create_conversation(**kwargs):
    """
    Create a conversation with an optional title. Scope is derived from JWT role
    (admin → ``admin``, everyone else → ``member``).

    Body: ``{ "title": "Optional title" }``
    """
    tenant_id = kwargs["tenant_id"]
    current_user = kwargs["current_user"]
    user_id = current_user.get("id")
    user_role = _resolve_user_role(current_user)
    scope = _chat_scope_for_role(user_role)

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    body = request.get_json(silent=True) or {}
    title = (body.get("title") or "New conversation").strip()
    if len(title) > _MAX_TITLE_LEN:
        return jsonify({"error": f"title must be at most {_MAX_TITLE_LEN} characters"}), 400

    conv_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    row = {
        "id": conv_id,
        "tenant_id": tenant_id,
        "title": title,
        "chat_scope": scope,
        "created_by": str(user_id),
        "created_at": now,
        "updated_at": now,
    }

    try:
        ins = execute_with_retry(
            lambda: supabase.table("chat_conversations").insert(row).execute()
        )
    except Exception as e:
        current_app.logger.exception("create_conversation failed")
        return jsonify({"error": f"Failed to create conversation: {e}"}), 500

    saved = (ins.data or [row])[0]
    return jsonify({"conversation": saved}), 201


@chats_bp.route("/chats/conversations/<conversation_id>", methods=["PATCH"])
@require_auth
def update_conversation(conversation_id: str, **kwargs):
    """Update conversation title. Body: ``{ "title": "..." }``."""
    if not _valid_uuid(conversation_id):
        return jsonify({"error": "Invalid conversation id"}), 400

    tenant_id = kwargs["tenant_id"]
    user_role = _resolve_user_role(kwargs["current_user"])
    scope = _chat_scope_for_role(user_role)

    body = request.get_json(silent=True) or {}
    title = (body.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title is required"}), 400
    if len(title) > _MAX_TITLE_LEN:
        return jsonify({"error": f"title must be at most {_MAX_TITLE_LEN} characters"}), 400

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    now = datetime.now(timezone.utc).isoformat()
    try:
        res = execute_with_retry(
            lambda: supabase.table("chat_conversations")
            .update({"title": title, "updated_at": now})
            .eq("id", conversation_id)
            .eq("tenant_id", tenant_id)
            .eq("chat_scope", scope)
            .execute()
        )
    except Exception as e:
        current_app.logger.exception("update_conversation failed")
        return jsonify({"error": f"Failed to update conversation: {e}"}), 500

    if not res.data:
        return jsonify({"error": "Conversation not found"}), 404

    return jsonify({"conversation": res.data[0]}), 200


@chats_bp.route("/chats/conversations/<conversation_id>", methods=["DELETE"])
@require_auth
def delete_conversation(conversation_id: str, **kwargs):
    """Delete a conversation and all of its messages (cascade)."""
    if not _valid_uuid(conversation_id):
        return jsonify({"error": "Invalid conversation id"}), 400

    tenant_id = kwargs["tenant_id"]
    user_role = _resolve_user_role(kwargs["current_user"])
    scope = _chat_scope_for_role(user_role)

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    try:
        res = execute_with_retry(
            lambda: supabase.table("chat_conversations")
            .delete()
            .eq("id", conversation_id)
            .eq("tenant_id", tenant_id)
            .eq("chat_scope", scope)
            .execute()
        )
    except Exception as e:
        current_app.logger.exception("delete_conversation failed")
        return jsonify({"error": f"Failed to delete conversation: {e}"}), 500

    if not res.data:
        return jsonify({"error": "Conversation not found"}), 404

    return jsonify({"message": "Conversation deleted", "id": conversation_id}), 200


def _get_conversation_or_404(
    supabase, tenant_id: str, scope: str, conversation_id: str
) -> Optional[Dict[str, Any]]:
    res = execute_with_retry(
        lambda: supabase.table("chat_conversations")
        .select("id, tenant_id, title, chat_scope, created_by, created_at, updated_at")
        .eq("id", conversation_id)
        .eq("tenant_id", tenant_id)
        .eq("chat_scope", scope)
        .limit(1)
        .execute()
    )
    if not res.data:
        return None
    return res.data[0]


@chats_bp.route("/chats/conversations/<conversation_id>/messages", methods=["GET"])
@require_auth
def list_messages(conversation_id: str, **kwargs):
    """
    List messages in a conversation (oldest first).

    Query: ``limit`` (default 100, max 500), ``before_id`` (optional UUID of message —
    return messages strictly older than that message's created_at for pagination).
    """
    if not _valid_uuid(conversation_id):
        return jsonify({"error": "Invalid conversation id"}), 400

    tenant_id = kwargs["tenant_id"]
    user_role = _resolve_user_role(kwargs["current_user"])
    scope = _chat_scope_for_role(user_role)

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    conv = _get_conversation_or_404(supabase, tenant_id, scope, conversation_id)
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404

    limit = request.args.get("limit", str(_DEFAULT_MESSAGE_PAGE))
    try:
        lim = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        lim = _DEFAULT_MESSAGE_PAGE

    before_id = (request.args.get("before_id") or "").strip()
    cursor_time: Optional[str] = None
    if before_id and _valid_uuid(before_id):
        cur = execute_with_retry(
            lambda: supabase.table("chat_messages")
            .select("created_at")
            .eq("id", before_id)
            .eq("conversation_id", conversation_id)
            .eq("tenant_id", tenant_id)
            .limit(1)
            .execute()
        )
        if cur.data:
            cursor_time = cur.data[0].get("created_at")

    try:
        q = (
            supabase.table("chat_messages")
            .select("id, conversation_id, role, content, metadata, created_at")
            .eq("conversation_id", conversation_id)
            .eq("tenant_id", tenant_id)
            .order("created_at", desc=False)
        )
        if cursor_time:
            q = q.lt("created_at", cursor_time)
        result = execute_with_retry(lambda: q.limit(lim).execute())
    except Exception as e:
        current_app.logger.exception("list_messages failed")
        return jsonify({"error": f"Failed to list messages: {e}"}), 500

    return jsonify(
        {
            "conversation": conv,
            "messages": result.data or [],
        }
    ), 200


@chats_bp.route("/chats/conversations/<conversation_id>/messages", methods=["POST"])
@require_auth
def append_message(conversation_id: str, **kwargs):
    """
    Append a message to a conversation.

    Body::
        {
          "role": "user" | "assistant" | "system",
          "content": "...",
          "metadata": {}   // optional JSON object
        }
    """
    if not _valid_uuid(conversation_id):
        return jsonify({"error": "Invalid conversation id"}), 400

    tenant_id = kwargs["tenant_id"]
    user_role = _resolve_user_role(kwargs["current_user"])
    scope = _chat_scope_for_role(user_role)

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    conv = _get_conversation_or_404(supabase, tenant_id, scope, conversation_id)
    if not conv:
        return jsonify({"error": "Conversation not found"}), 404

    body = request.get_json(silent=True) or {}
    role = (body.get("role") or "").strip().lower()
    content = body.get("content")
    if role not in _ALLOWED_MESSAGE_ROLES:
        return jsonify(
            {"error": f"role must be one of: {sorted(_ALLOWED_MESSAGE_ROLES)}"}
        ), 400
    if content is None or not isinstance(content, str):
        return jsonify({"error": "content must be a string"}), 400
    if not content.strip():
        return jsonify({"error": "content must not be empty"}), 400
    if len(content) > _MAX_MESSAGE_CHARS:
        return jsonify(
            {"error": f"content must be at most {_MAX_MESSAGE_CHARS} characters"}
        ), 400

    meta = body.get("metadata")
    if meta is not None and not isinstance(meta, dict):
        return jsonify({"error": "metadata must be a JSON object if provided"}), 400
    if meta is None:
        meta = {}

    msg_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    row = {
        "id": msg_id,
        "conversation_id": conversation_id,
        "tenant_id": tenant_id,
        "role": role,
        "content": content,
        "metadata": meta,
        "created_at": now,
    }

    try:
        ins = execute_with_retry(
            lambda: supabase.table("chat_messages").insert(row).execute()
        )
        execute_with_retry(
            lambda: supabase.table("chat_conversations")
            .update({"updated_at": now})
            .eq("id", conversation_id)
            .eq("tenant_id", tenant_id)
            .execute()
        )
    except Exception as e:
        current_app.logger.exception("append_message failed")
        return jsonify({"error": f"Failed to save message: {e}"}), 500

    saved = (ins.data or [row])[0]
    return jsonify({"message": saved}), 201
