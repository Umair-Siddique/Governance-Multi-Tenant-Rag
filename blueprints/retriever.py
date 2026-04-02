"""
Tenant-scoped RAG retriever: query the tenant's Pinecone index, optional LLM-built metadata
filters from natural language, then stream an answer with SSE status updates.
"""
import json
import logging
from typing import Any, Dict, Generator, List, Optional

from flask import Blueprint, Response, current_app, jsonify, request, stream_with_context

from config import Config
from utils.auth_helpers import require_auth

logger = logging.getLogger(__name__)

retriever_bp = Blueprint("retriever", __name__)

_FILTER_SYSTEM = """You are a query planner for semantic search over document chunks stored in Pinecone.

Each vector has metadata (all string values unless noted):
- document_id: UUID string for PDF/DOCX chunks (source_type "document")
- file_id: UUID string for CSV chunks (source_type "csv")
- source_type: "document" or "csv"
- filename: original file name
- chunk_index: integer (only use in filters if the user asks for a specific chunk number)
- tenant_id: UUID (do not filter on this; the backend already scopes by tenant index)

Return a single JSON object with exactly these keys:
- "search_query": string — concise text optimized for embedding / similarity search (main topic + intent)
- "pinecone_filter": null OR a Pinecone metadata filter using only: $eq, $in, $and, $or, $ne on the metadata fields above
- "reasoning": one short sentence describing what you interpreted (optional, may be empty string)

Rules:
- If the user names a specific document UUID (e.g. in a "doc_..." or standard UUID form), use document_id with $eq when source is clearly a normal document, or file_id for CSV if they say CSV/dataset.
- If they give an exact file name, use "filename" with $eq.
- If the question is general or spans all docs, set pinecone_filter to null.
- Do not invent UUIDs; only use an id if it appears verbatim in the user message.

Examples:
User: Give me a summary of document 550e8400-e29b-41d4-a716-446655440000
-> search_query: "main themes summary overview", pinecone_filter: {"document_id": {"$eq": "550e8400-e29b-41d4-a716-446655440000"}}

User: What does quarterly report.pdf say about revenue?
-> search_query: "revenue financial results quarterly", pinecone_filter: {"filename": {"$eq": "quarterly report.pdf"}}
"""


def _sse(event: str, data: Dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _plan_search(
    openai_client,
    user_query: str,
) -> tuple[str, Optional[dict], Optional[str], Optional[str]]:
    """
    Returns (search_query, pinecone_filter_or_none, reasoning, error_message).
    On planner failure, falls back to raw user_query with no filter.
    """
    try:
        resp = openai_client.chat.completions.create(
            model=Config.RETRIEVER_FILTER_MODEL,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _FILTER_SYSTEM},
                {"role": "user", "content": user_query},
            ],
            temperature=0.2,
        )
        raw = (resp.choices[0].message.content or "{}").strip()
        data = json.loads(raw)
        search_query = (data.get("search_query") or "").strip() or user_query
        pf = data.get("pinecone_filter")
        if pf is not None and not isinstance(pf, dict):
            pf = None
        reasoning = (data.get("reasoning") or "").strip() or None
        return search_query, pf, reasoning, None
    except Exception as e:
        logger.warning("Retriever filter planning failed: %s", e)
        return user_query, None, None, str(e)


def _embed_query(openai_client, text: str) -> List[float]:
    r = openai_client.embeddings.create(
        model=Config.RETRIEVER_EMBEDDING_MODEL,
        input=text[:8000],
        dimensions=1536,
    )
    return list(r.data[0].embedding)


def _format_matches_for_prompt(matches: List[Any]) -> str:
    parts = []
    for i, m in enumerate(matches, start=1):
        meta = getattr(m, "metadata", None) or {}
        if not isinstance(meta, dict):
            meta = {}
        score = getattr(m, "score", None)
        content = meta.get("content") or ""
        fname = meta.get("filename") or ""
        doc_id = meta.get("document_id") or meta.get("file_id") or ""
        src = meta.get("source_type") or ""
        header = f"[{i}] score={score:.4f}" if score is not None else f"[{i}]"
        parts.append(
            f"{header} filename={fname} id={doc_id} source={src}\n{content}\n"
        )
    return "\n---\n".join(parts) if parts else "(no chunks retrieved)"


def _stream_retrieval(
    tenant_id: str,
    user_query: str,
    top_k: int,
) -> Generator[str, None, None]:
    yield _sse("status", {"stage": "received", "message": "Received your question"})

    openai_client = getattr(current_app, "openai_service", None)
    if not openai_client or not Config.OPENAI_API_KEY:
        yield _sse(
            "error",
            {"message": "OpenAI is not configured (OPENAI_API_KEY missing)."},
        )
        return

    pc = getattr(current_app, "pinecone_service", None)
    if not pc:
        yield _sse(
            "error",
            {"message": "Pinecone is not configured (PINECONE_API_KEY missing)."},
        )
        return

    yield _sse(
        "status",
        {"stage": "analyzing_query", "message": "Understanding your question and optional filters"},
    )

    search_query, pinecone_filter, reasoning, plan_err = _plan_search(openai_client, user_query)
    payload: Dict[str, Any] = {
        "search_query": search_query,
        "pinecone_filter": pinecone_filter,
    }
    if reasoning:
        payload["reasoning"] = reasoning
    if plan_err:
        payload["planner_note"] = "Used fallback search (planner error)"
    yield _sse("plan", payload)

    yield _sse(
        "status",
        {"stage": "embedding", "message": "Embedding search query"},
    )

    try:
        vector = _embed_query(openai_client, search_query)
    except Exception as e:
        logger.exception("Embedding failed")
        yield _sse("error", {"message": f"Embedding failed: {e}"})
        return

    yield _sse(
        "status",
        {"stage": "searching_data_source", "message": "Searching your tenant knowledge index"},
    )

    try:
        index = pc.get_index(tenant_id)
    except Exception as e:
        logger.exception("Pinecone index unavailable")
        yield _sse(
            "error",
            {"message": f"Vector index not available: {e}"},
        )
        return

    try:
        q_kwargs: Dict[str, Any] = {
            "vector": vector,
            "top_k": top_k,
            "include_metadata": True,
        }
        if pinecone_filter and isinstance(pinecone_filter, dict) and len(pinecone_filter) > 0:
            q_kwargs["filter"] = pinecone_filter
        raw = index.query(**q_kwargs)
    except Exception as e:
        logger.exception("Pinecone query failed")
        yield _sse(
            "error",
            {"message": f"Search failed: {e}"},
        )
        return

    matches: List[Any] = []
    if raw is not None:
        m = getattr(raw, "matches", None)
        if m is None and isinstance(raw, dict):
            m = raw.get("matches")
        matches = list(m) if m else []

    yield _sse(
        "status",
        {
            "stage": "retrieved",
            "message": f"Retrieved {len(matches)} chunk(s) from the index",
            "match_count": len(matches),
        },
    )

    context = _format_matches_for_prompt(matches)

    yield _sse(
        "status",
        {"stage": "generating_response", "message": "Generating answer from retrieved context"},
    )

    system_msg = (
        "You are a helpful assistant. Answer using ONLY the provided context chunks. "
        "If the context is insufficient, say so briefly. Cite chunk numbers [1], [2] when relevant."
    )
    user_msg = f"Question:\n{user_query}\n\nContext:\n{context}"

    try:
        stream = openai_client.chat.completions.create(
            model=Config.RETRIEVER_CHAT_MODEL,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            stream=True,
            temperature=0.3,
        )
        for chunk in stream:
            choice = chunk.choices[0] if chunk.choices else None
            if not choice:
                continue
            delta = getattr(choice.delta, "content", None) if choice.delta else None
            if delta:
                yield _sse("token", {"text": delta})
    except Exception as e:
        logger.exception("Chat stream failed")
        yield _sse("error", {"message": f"Response generation failed: {e}"})
        return

    yield _sse("status", {"stage": "complete", "message": "Done"})
    yield _sse("done", {})


@retriever_bp.route("/retriever/stream", methods=["POST"])
@require_auth
def retriever_stream(**kwargs):
    """
    Stream a retrieval-augmented answer as Server-Sent Events.

    Request JSON:
      - query (required): user question
      - top_k (optional): max chunks (default 8, max 20)

    SSE events:
      - status: { stage, message, ... }
      - plan: { search_query, pinecone_filter, ... }
      - token: { text } — streamed answer fragments
      - done: {}
      - error: { message }
    """
    tenant_id = kwargs["tenant_id"]
    body = request.get_json(silent=True) or {}
    user_query = (body.get("query") or body.get("question") or "").strip()
    if not user_query:
        return jsonify({"error": "query (or question) is required"}), 400

    top_k = body.get("top_k", 8)
    try:
        top_k = int(top_k)
    except (TypeError, ValueError):
        top_k = 8
    top_k = max(1, min(top_k, 20))

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }

    return Response(
        stream_with_context(_stream_retrieval(tenant_id, user_query, top_k)),
        mimetype="text/event-stream",
        headers=headers,
    )
