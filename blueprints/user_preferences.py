"""
User preferences APIs (tenant-scoped, per-user).

v1: explicit preferred language selection for retriever answers.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from flask import Blueprint, current_app, jsonify, request

from utils.auth_helpers import require_auth
from utils.supabase_retry import execute_with_retry

user_preferences_bp = Blueprint("user_preferences", __name__)

_SUPPORTED_LANGUAGES = [
    # Multilingual Support (section 10.1)
    "Arabic",
    "Tigrinya",
    "Farsi",
    "Dari",
    "Pashto",
    "Turkish",
    "Somali",
    "English",
    "French",
    "Dutch",
    # v1 priority languages (explicitly called out later)
    "German",
    "Spanish",
]

_LANG_LOOKUP = {k.lower(): k for k in _SUPPORTED_LANGUAGES}


def _normalize_language(val: Any) -> str:
    raw = str(val or "").strip()
    if not raw:
        return "English"
    key = raw.lower()
    return _LANG_LOOKUP.get(key, "")


def _get_or_default_language(supabase, tenant_id: str, user_id: str) -> str:
    res = execute_with_retry(
        lambda: supabase.table("user_preferences")
        .select("preferred_language")
        .eq("tenant_id", tenant_id)
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    if res.data:
        lang = (res.data[0].get("preferred_language") or "").strip()
        return lang or "English"
    return "English"


@user_preferences_bp.route("/user/preferences/language", methods=["GET"])
@require_auth
def get_language(**kwargs):
    tenant_id = kwargs["tenant_id"]
    user_id = str((kwargs["current_user"] or {}).get("id") or "").strip()
    if not user_id:
        return jsonify({"error": "User id missing from token"}), 401

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    try:
        lang = _get_or_default_language(supabase, tenant_id, user_id)
    except Exception as e:
        current_app.logger.exception("get_language failed")
        return jsonify({"error": f"Failed to get language preference: {e}"}), 500

    return (
        jsonify(
            {
                "preferred_language": lang,
                "supported_languages": _SUPPORTED_LANGUAGES,
                "default_language": "English",
            }
        ),
        200,
    )


@user_preferences_bp.route("/user/preferences/language", methods=["PUT"])
@require_auth
def set_language(**kwargs):
    """
    Set preferred language explicitly (no auto-detection).

    Body: { "language": "English" }  (alias: preferred_language)
    """
    tenant_id = kwargs["tenant_id"]
    user_id = str((kwargs["current_user"] or {}).get("id") or "").strip()
    if not user_id:
        return jsonify({"error": "User id missing from token"}), 401

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    body: Dict[str, Any] = request.get_json(silent=True) or {}
    lang = _normalize_language(body.get("language") or body.get("preferred_language"))
    if not lang:
        return (
            jsonify(
                {
                    "error": "Unsupported language",
                    "supported_languages": _SUPPORTED_LANGUAGES,
                    "default_language": "English",
                }
            ),
            400,
        )

    now = datetime.now(timezone.utc).isoformat()
    row = {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "preferred_language": lang,
        "updated_at": now,
    }

    try:
        # Upsert (tenant_id, user_id) unique
        res = execute_with_retry(
            lambda: supabase.table("user_preferences")
            .upsert(row, on_conflict="tenant_id,user_id")
            .execute()
        )
    except Exception as e:
        current_app.logger.exception("set_language failed")
        return jsonify({"error": f"Failed to set language preference: {e}"}), 500

    saved = (res.data or [row])[0]
    return jsonify({"preference": saved, "supported_languages": _SUPPORTED_LANGUAGES}), 200

