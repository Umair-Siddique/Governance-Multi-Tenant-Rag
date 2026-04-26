"""
Tenant-scoped retriever API with streamed OpenAI responses.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from flask import Blueprint, Response, current_app, jsonify, request, stream_with_context

from utils.auth_helpers import get_user_from_token
from utils.llm_providers import resolve_tenant_openai_for_retriever
from utils.retriever_langchain_tools import (
    build_retrieval_tools,
    matches_from_tool_state,
    run_retrieval_tool_agent,
)

retriever_bp = Blueprint("retriever", __name__)

_MAX_QUERY_LEN = 8000
_DEFAULT_TOP_K = 8
_MAX_TOP_K = 20
_FINAL_CONTEXT_CAP = 16

_ANSWER_SYSTEM_PROMPT = """You are a precise assistant for tenant-scoped governance knowledge.

Rules:
- Use only the provided retrieved context.
- If context is missing or insufficient, say so clearly and ask for a more specific question.
- Keep answers concise and factual.
- Do not mention internal tool names or system internals.
"""


def _sse(event: str, payload: Dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

def _sse_comment(text: str) -> str:
    # SSE comment lines start with ":" and are ignored by EventSource,
    # but still force bytes to flush through proxies/buffers.
    return f": {text}\n\n"


def _clamp_top_k(raw: Any) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = _DEFAULT_TOP_K
    return max(1, min(value, _MAX_TOP_K))


def _safe_meta(m: Any) -> Dict[str, Any]:
    meta = getattr(m, "metadata", None) or {}
    return meta if isinstance(meta, dict) else {}


def _build_context(matches: List[Any]) -> str:
    blocks: List[str] = []
    for idx, m in enumerate(matches, start=1):
        meta = _safe_meta(m)
        score = getattr(m, "score", None)
        score_text = ""
        if score is not None:
            try:
                score_text = f"{float(score):.4f}"
            except (TypeError, ValueError):
                score_text = str(score)
        blocks.append(
            "\n".join(
                [
                    f"[{idx}]",
                    f"source_type: {meta.get('source_type') or ''}",
                    f"filename: {meta.get('filename') or ''}",
                    f"document_id: {meta.get('document_id') or meta.get('file_id') or ''}",
                    f"chunk_index: {meta.get('chunk_index') if meta.get('chunk_index') is not None else ''}",
                    f"score: {score_text}",
                    f"content: {meta.get('content') or ''}",
                ]
            )
        )
    return "\n\n".join(blocks)


@retriever_bp.route("/retriever/query/stream", methods=["POST"])
def stream_retriever_answer(**kwargs):
    """
    Stream a tenant-scoped RAG answer as SSE.

    Body:
      {
        "query": "user question",
        "top_k": 8   # optional, max 20
      }
    """
    body = request.get_json(silent=True) or {}
    query = (body.get("query") or "").strip()
    if not query:
        return jsonify({"error": "query is required"}), 400
    if len(query) > _MAX_QUERY_LEN:
        return jsonify({"error": f"query must be at most {_MAX_QUERY_LEN} characters"}), 400

    top_k = _clamp_top_k(body.get("top_k"))

    def generate():
        message_id = datetime.now(timezone.utc).isoformat()
        # 1) Force immediate flush through proxy buffers (2KB+ comment padding).
        yield _sse_comment("ping " + ("0" * 16384))

        # 2) Send start event immediately (before any auth/retrieval).
        yield _sse(
            "start",
            {
                "message_id": message_id,
                "stage": "auth",
                "ts": message_id,
            },
        )

        try:
            user_data, auth_error = get_user_from_token()
            if auth_error or not user_data:
                yield _sse("error", {"message": auth_error or "Unauthorized"})
                return

            tenant_id = user_data.get("tenant_id")
            if not tenant_id:
                yield _sse("error", {"message": "User is not associated with a tenant"})
                return

            yield _sse(
                "start",
                {
                    "message_id": message_id,
                    "tenant_id": tenant_id,
                    "stage": "retrieving",
                    "ts": message_id,
                },
            )

            supabase = current_app.supabase_client
            encryption_service = getattr(current_app, "encryption_service", None)
            pinecone_service = getattr(current_app, "pinecone_service", None)
            if not pinecone_service:
                yield _sse("error", {"message": "Pinecone service is not configured"})
                return

            openai_client, chat_model, filter_model, embedding_model, oai_error = (
                resolve_tenant_openai_for_retriever(
                    supabase=supabase,
                    tenant_id=tenant_id,
                    encryption_service=encryption_service,
                )
            )
            if oai_error:
                yield _sse("error", {"message": oai_error})
                return

            try:
                index = pinecone_service.get_index(tenant_id)
                namespace = pinecone_service.get_tenant_namespace(tenant_id)
            except Exception as e:
                current_app.logger.exception("Failed to prepare tenant namespace/index")
                yield _sse("error", {"message": f"Retriever storage unavailable: {e}"})
                return

            tools, tool_state = build_retrieval_tools(
                openai_client=openai_client,
                embedding_model=embedding_model,
                index=index,
                namespace=namespace,
                request_top_k=top_k,
            )

            # Keep connection alive / visibly streaming while retrieval planning runs.
            # (Also helps some proxies avoid considering the response idle.)
            t0 = time.time()
            yield _sse_comment("hb " + message_id)

            had_tool_call, tool_error = run_retrieval_tool_agent(
                openai_client=openai_client,
                filter_model=filter_model,
                user_query=query,
                tools=tools,
                state=tool_state,
            )
            if tool_error:
                current_app.logger.warning("Retriever tool planner failed: %s", tool_error)

            if not had_tool_call and tools:
                try:
                    tools[0].invoke({"query": query, "top_k": top_k})
                except Exception:
                    current_app.logger.exception("Fallback semantic retrieval failed")

            matches = matches_from_tool_state(
                tool_state, cap=min(max(top_k, _DEFAULT_TOP_K), _FINAL_CONTEXT_CAP)
            )
            if not matches:
                yield _sse(
                    "error",
                    {
                        "message": (
                            "No context found in your tenant knowledge base. "
                            "Upload and publish documents/CSV files to Pinecone, then try again."
                        )
                    },
                )
                return

            yield _sse(
                "context",
                {
                    "message_id": message_id,
                    "stage": "answering",
                    "match_count": len(matches),
                    "retrieval_ms": int((time.time() - t0) * 1000),
                },
            )

            rag_context = _build_context(matches)
            user_prompt = (
                f"Question:\n{query}\n\n"
                f"Retrieved context (tenant-scoped):\n{rag_context}\n\n"
                "Answer the question using only this context."
            )

            stream = openai_client.chat.completions.create(
                model=chat_model,
                messages=[
                    {"role": "system", "content": _ANSWER_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                stream=True,
            )
            for chunk in stream:
                if not chunk or not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                token = getattr(delta, "content", None)
                if token:
                    yield _sse("delta", {"content": token})
            yield _sse(
                "end",
                {
                    "message_id": message_id,
                    "match_count": len(matches),
                    "tool_trace": tool_state.get("tool_trace") or [],
                },
            )
        except Exception as e:
            current_app.logger.exception("Streaming retriever response failed")
            yield _sse("error", {"message": str(e)})

    resp = Response(stream_with_context(generate()), mimetype="text/event-stream")
    # Extra safety for common buffering layers (in addition to app.after_request).
    resp.headers["Cache-Control"] = "no-cache, no-transform"
    resp.headers["X-Accel-Buffering"] = "no"
    resp.headers.pop("Content-Length", None)
    return resp

