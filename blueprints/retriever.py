"""
Tenant-scoped RAG retriever: query the tenant's Pinecone namespace in the shared index,
then stream an answer with SSE status updates.

Retrieval first runs a LangChain tool-calling pass (OpenAI): ``semantic_search``,
``search_documents`` (PDF/DOCX + optional metadata filters), and ``search_csv_dataset``
(CSV chunks + optional ``file_id`` / filename filters). If no tool-produced hits are
returned, the legacy JSON query planner + single Pinecone query is used unchanged.

Optional temporary files: send multipart/form-data with field ``query`` (or ``question``)
and one or more ``file`` parts (same name as bulk upload). JSON body without files
is unchanged. Embeddings + query planner always use the tenant's active OpenAI row;
the final answer streams from the most recently updated active provider (openai,
anthropic, or mistral).
"""
import base64
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import io
import json
import logging
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

import anthropic
from flask import Blueprint, Response, current_app, jsonify, request, stream_with_context
from werkzeug.utils import secure_filename

from config import Config
from utils.auth_helpers import require_auth
from utils.document_utils import extract_text_from_docx, extract_text_from_image, extract_text_from_pdf
from utils.llm_providers import resolve_tenant_openai_for_retriever, resolve_tenant_primary_answer_provider
from utils.supabase_retry import execute_with_retry
from utils.retriever_langchain_tools import (
    build_retrieval_tools,
    matches_from_tool_state,
    run_retrieval_tool_agent,
)

logger = logging.getLogger(__name__)

retriever_bp = Blueprint("retriever", __name__)

_MAX_TEMP_FILES = 12
_MAX_BYTES_PER_FILE = 15 * 1024 * 1024
_MAX_INJECTED_TEXT = 100_000
_OPENAI_VISION_MIMES = {"image/jpeg", "image/png", "image/gif", "image/webp"}

_FILTER_SYSTEM = """You are a query planner for semantic search over document chunks stored in Pinecone.

Each vector has metadata (all string values unless noted):
- document_id: UUID string for PDF/DOCX chunks (source_type "document")
- file_id: UUID string for CSV chunks (source_type "csv")
- source_type: "document" or "csv"
- filename: original file name
- chunk_index: integer (only use in filters if the user asks for a specific chunk number)
- tenant_id: UUID (do not filter on this; the backend already scopes by Pinecone namespace)

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

_V1_SUPPORTED_LANGUAGES = [
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
    "German",
    "Spanish",
]


def _get_user_preferred_language(supabase, tenant_id: str, user_id: str) -> str:
    """
    Explicit selection only (no auto-detection). Defaults to English.
    """
    if not supabase or not tenant_id or not user_id:
        return "English"
    try:
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
    except Exception:
        # Non-fatal: fall back to English.
        pass
    return "English"


def _strict_language_system_prompt(language: str) -> str:
    lang = (language or "English").strip() or "English"
    if lang not in _V1_SUPPORTED_LANGUAGES:
        lang = "English"
    return (
        "SYSTEM (GOVERNANCE + LANGUAGE ENFORCEMENT)\n"
        "You are a governance-safe retrieval assistant.\n\n"
        "You MUST follow these rules:\n"
        "1) Use ONLY the provided 'Retrieved context from the knowledge base' and any 'User-attached files' text.\n"
        "2) Do NOT use outside knowledge. Do NOT browse. Do NOT guess.\n"
        "3) If the context is insufficient to answer, you MUST say you don't have enough information from the provided data.\n"
        "4) Provide citations using chunk numbers like [1], [2] when you use retrieved context.\n"
        "5) LANGUAGE RULE (STRICT): Answer ONLY in this language: "
        f"{lang}.\n"
        "   - No auto-detection.\n"
        "   - No language mixing.\n"
        "   - If the user asks for a different language than the selected one, refuse and still respond ONLY in the selected language.\n"
    )


def _sse(event: str, data: Dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _parse_stream_request() -> Tuple[str, int, List[Tuple[str, bytes, str]]]:
    """Returns (user_query, top_k, attachments) where each attachment is (filename, raw_bytes, content_type)."""
    attachments: List[Tuple[str, bytes, str]] = []
    top_k = 8

    ct = (request.content_type or "").lower()
    if "multipart/form-data" in ct:
        user_query = (request.form.get("query") or request.form.get("question") or "").strip()
        tk = request.form.get("top_k")
        if tk not in (None, ""):
            try:
                top_k = int(tk)
            except (TypeError, ValueError):
                top_k = 8
        files = request.files.getlist("file")
        for f in files:
            if not f or not getattr(f, "filename", None):
                continue
            raw = f.read()
            attachments.append(
                (f.filename, raw, (f.content_type or "application/octet-stream").strip())
            )
    else:
        body = request.get_json(silent=True) or {}
        user_query = (body.get("query") or body.get("question") or "").strip()
        tk = body.get("top_k", 8)
        try:
            top_k = int(tk)
        except (TypeError, ValueError):
            top_k = 8

    top_k = max(1, min(top_k, 20))
    return user_query, top_k, attachments


def _safe_filename(name: str) -> str:
    base = secure_filename(name or "") or "upload"
    return base[:200] if len(base) > 200 else base


def _extract_uploaded_text(filename: str, data: bytes, content_type: str) -> str:
    """Best-effort text for RAG / prompt injection (PDF, DOCX, plain text, CSV, images via OCR)."""
    ext = Path(filename).suffix.lower()
    tess = Config.TESSERACT_CMD
    try:
        if ext == ".pdf":
            return (extract_text_from_pdf(data, tesseract_cmd=tess) or "").strip()
        if ext == ".docx":
            return (extract_text_from_docx(data, tesseract_cmd=tess) or "").strip()
        if ext in (".txt", ".md", ".csv", ".json", ".log"):
            return data.decode("utf-8", errors="replace").strip()
        if ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}:
            return (extract_text_from_image(data, tesseract_cmd=tess) or "").strip()
    except Exception as e:
        logger.warning("Temp file text extraction failed for %s: %s", filename, e)
    return ""


def _build_attachment_bundle(
    attachments: List[Tuple[str, bytes, str]],
) -> Dict[str, Any]:
    """
    Build structures for the final LLM call.
    Returns keys: text_digest, openai_image_parts, anthropic_pdf_native (list of tuples name,bytes,mime)
    """
    text_parts: List[str] = []
    openai_image_parts: List[Dict[str, Any]] = []
    anthropic_pdf_native: List[Tuple[str, bytes, str]] = []
    anthropic_image_blocks: List[Dict[str, Any]] = []

    n = 0
    for raw_name, data, ctype in attachments:
        if n >= _MAX_TEMP_FILES:
            break
        if len(data) > _MAX_BYTES_PER_FILE:
            text_parts.append(f"### {_safe_filename(raw_name)}\n(skipped: file larger than {_MAX_BYTES_PER_FILE // (1024 * 1024)} MB)\n")
            n += 1
            continue
        name = _safe_filename(raw_name)
        ext = Path(name).suffix.lower()
        lower_ct = (ctype or "").split(";")[0].strip().lower()

        if ext == ".pdf" or lower_ct == "application/pdf":
            anthropic_pdf_native.append((name, data, "application/pdf"))
            extracted = _extract_uploaded_text(name, data, ctype)
            if extracted:
                text_parts.append(f"### {name}\n{extracted}\n")
            else:
                text_parts.append(f"### {name}\n(no extractable text; PDF attached for vision-capable flows)\n")
        elif ext == ".docx" or "wordprocessingml" in lower_ct:
            extracted = _extract_uploaded_text(name, data, ctype)
            text_parts.append(f"### {name}\n{extracted or '(no text extracted)'}\n")
        elif lower_ct in _OPENAI_VISION_MIMES or ext in {".jpg", ".jpeg", ".png", ".gif", ".webp"}:
            mime = lower_ct if lower_ct in _OPENAI_VISION_MIMES else {
                ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
                ".gif": "image/gif", ".webp": "image/webp",
            }.get(ext, "image/png")
            b64 = base64.b64encode(data).decode("ascii")
            openai_image_parts.append(
                {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}}
            )
            anthropic_image_blocks.append(
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": mime,
                        "data": b64,
                    },
                }
            )
            ocr = _extract_uploaded_text(name, data, ctype)
            if ocr:
                text_parts.append(f"### {name} (OCR)\n{ocr}\n")
        else:
            extracted = _extract_uploaded_text(name, data, ctype)
            text_parts.append(f"### {name}\n{extracted or '(binary or unsupported type; no text extracted)'}\n")

        n += 1

    digest = "\n".join(text_parts).strip()
    if len(digest) > _MAX_INJECTED_TEXT:
        digest = digest[:_MAX_INJECTED_TEXT] + "\n\n[Attachment text truncated]\n"

    return {
        "text_digest": digest,
        "openai_image_parts": openai_image_parts,
        "anthropic_pdf_native": anthropic_pdf_native,
        "anthropic_image_blocks": anthropic_image_blocks,
    }


def _plan_search(
    openai_client,
    user_query: str,
    filter_model: str,
) -> tuple[str, Optional[dict], Optional[str], Optional[str]]:
    try:
        resp = openai_client.chat.completions.create(
            model=filter_model,
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


def _embed_query(openai_client, text: str, embedding_model: str) -> List[float]:
    r = openai_client.embeddings.create(
        model=embedding_model,
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


def _default_model_for_provider(provider: str, configured: str) -> str:
    if (configured or "").strip():
        return configured.strip()
    defaults = {
        "openai": Config.RETRIEVER_CHAT_MODEL,
        "anthropic": "claude-haiku-4-5-20251001",
        "mistral": "mistral-small-latest",
    }
    return defaults.get(provider, Config.RETRIEVER_CHAT_MODEL)


def _stream_openai_chat(
    openai_client,
    model: str,
    system_msg: str,
    user_text: str,
    image_parts: List[Dict[str, Any]],
) -> Generator[str, None, None]:
    if image_parts:
        user_content: Any = [{"type": "text", "text": user_text}, *image_parts]
    else:
        user_content = user_text
    stream = openai_client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_content},
        ],
        stream=True,
        temperature=0.3,
    )
    for chunk in stream:
        choices = getattr(chunk, "choices", None) or []
        choice = choices[0] if choices else None
        if choice is None:
            continue
        # OpenAI SDKs/models differ: streamed text can appear under delta.content, message.content, or text.
        delta_obj = getattr(choice, "delta", None)
        msg_obj = getattr(choice, "message", None)
        pieces = [
            getattr(delta_obj, "content", None) if delta_obj is not None else None,
            getattr(msg_obj, "content", None) if msg_obj is not None else None,
            getattr(choice, "text", None),
        ]
        for piece in pieces:
            if piece:
                yield _sse("token", {"text": piece})


def _stream_anthropic_chat(
    api_key: str,
    model: str,
    system_msg: str,
    user_text: str,
    bundle: Dict[str, Any],
) -> Generator[str, None, None]:
    client = anthropic.Anthropic(api_key=api_key)
    pdfs: List[Tuple[str, bytes, str]] = bundle.get("anthropic_pdf_native") or []
    img_blocks: List[Dict[str, Any]] = bundle.get("anthropic_image_blocks") or []

    file_ids: List[str] = []
    if pdfs:
        yield _sse(
            "status",
            {
                "stage": "anthropic_uploads",
                "message": f"Uploading {min(len(pdfs), 5)} PDF(s) for better answers",
                "pdf_count": min(len(pdfs), 5),
            },
        )
    for name, raw, mime in pdfs[:5]:
        try:
            up = client.beta.files.upload(file=(name, io.BytesIO(raw), mime))
        except Exception:
            try:
                up = client.files.upload(file=(name, io.BytesIO(raw), mime))
            except Exception as e:
                logger.warning("Anthropic PDF upload failed for %s: %s", name, e)
                continue
        fid = getattr(up, "id", None) or (up.get("id") if isinstance(up, dict) else None)
        if fid:
            file_ids.append(str(fid))

    content: List[Dict[str, Any]] = [{"type": "text", "text": user_text}]
    for fid in file_ids:
        content.append({"type": "document", "source": {"type": "file", "file_id": fid}})
    content.extend(img_blocks)

    try:
        yield _sse(
            "status",
            {
                "stage": "provider_stream_start",
                "message": "Starting model response stream",
                "provider": "anthropic",
                "model": model,
            },
        )
        kwargs: Dict[str, Any] = {
            "model": model,
            "max_tokens": 4096,
            "system": system_msg,
            "messages": [{"role": "user", "content": content}],
        }
        if file_ids:
            kwargs["betas"] = ["files-api-2025-04-14"]
        with client.messages.stream(**kwargs) as stream:
            for text in stream.text_stream:
                if text:
                    yield _sse("token", {"text": text})
    except Exception as e:
        logger.warning("Anthropic stream with attachments failed (%s); retrying text-only.", e)
        with client.messages.stream(
            model=model,
            max_tokens=4096,
            system=system_msg,
            messages=[{"role": "user", "content": user_text}],
        ) as stream:
            for text in stream.text_stream:
                if text:
                    yield _sse("token", {"text": text})


def _stream_mistral_chat(api_key: str, model: str, system_msg: str, user_text: str) -> Generator[str, None, None]:
    try:
        from mistralai import Mistral
    except ImportError:
        yield _sse("error", {"message": "Mistral SDK not installed (mistralai package)."})
        return

    client = Mistral(api_key=api_key)
    # Plain-text path with optional system preamble (Mistral chat accepts system in messages on many models)
    messages = []
    if system_msg:
        messages.append({"role": "system", "content": system_msg})
    messages.append({"role": "user", "content": user_text})

    try:
        stream_response = client.chat.stream(model=model, messages=messages)
        for chunk in stream_response:
            piece = None
            data = getattr(chunk, "data", None)
            if data is not None:
                choices = getattr(data, "choices", None) or []
                if choices:
                    delta = getattr(choices[0], "delta", None)
                    piece = getattr(delta, "content", None) if delta is not None else None
            if piece is None and hasattr(chunk, "choices") and chunk.choices:
                delta = getattr(chunk.choices[0], "delta", None)
                piece = getattr(delta, "content", None) if delta is not None else None
            if piece:
                yield _sse("token", {"text": piece})
    except Exception as e:
        logger.exception("Mistral stream failed")
        yield _sse("error", {"message": f"Mistral streaming failed: {e}"})


def _stream_retrieval(
    tenant_id: str,
    user_id: str,
    user_query: str,
    top_k: int,
    attachments: List[Tuple[str, bytes, str]],
) -> Generator[str, None, None]:
    yield _sse("status", {"stage": "received", "message": "Received your question"})

    supabase = getattr(current_app, "supabase_client", None)
    encryption_service = getattr(current_app, "encryption_service", None)
    openai_client, chat_model_oai, filter_model, embedding_model, llm_err = (
        resolve_tenant_openai_for_retriever(supabase, tenant_id, encryption_service)
    )
    if llm_err or not openai_client:
        yield _sse(
            "error",
            {"message": llm_err or "OpenAI is not configured for this tenant (required for embeddings)."},
        )
        return

    ptype, pkey, pmodel, perr = resolve_tenant_primary_answer_provider(
        supabase, tenant_id, encryption_service
    )
    if perr or not ptype:
        ptype = "openai"
        pkey = None
        pmodel = chat_model_oai
    answer_model = _default_model_for_provider(ptype, pmodel)

    # User-selected language (explicit, no auto-detection). Default is English.
    preferred_language = _get_user_preferred_language(supabase, tenant_id, user_id)

    bundle = _build_attachment_bundle(attachments) if attachments else {
        "text_digest": "",
        "openai_image_parts": [],
        "anthropic_pdf_native": [],
        "anthropic_image_blocks": [],
    }
    if attachments:
        yield _sse(
            "status",
            {
                "stage": "attachments",
                "message": f"Processed {len(attachments)} attached file(s)",
                "has_text_digest": bool(bundle["text_digest"]),
                "openai_images": len(bundle["openai_image_parts"]),
                "anthropic_pdfs": len(bundle["anthropic_pdf_native"]),
            },
        )

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

    # Keepalive so clients see immediate streaming progress even while planning/tools run.
    yield _sse("status", {"stage": "planning_retrieval", "message": "Planning retrieval tools"})

    try:
        index = pc.get_index(tenant_id)
        namespace = pc.get_tenant_namespace(tenant_id)
    except Exception as e:
        logger.exception("Pinecone index unavailable")
        yield _sse(
            "error",
            {"message": f"Vector index not available: {e}"},
        )
        return

    tools, tool_state = build_retrieval_tools(
        openai_client,
        embedding_model,
        index,
        namespace,
        top_k,
    )
    yield _sse("status", {"stage": "running_tools", "message": "Running retrieval tools"})
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(
                run_retrieval_tool_agent,
                openai_client,
                filter_model,
                user_query,
                tools,
                tool_state,
            )
            hb = 0
            while True:
                try:
                    _had_tool_calls, tool_agent_err = fut.result(timeout=1.5)
                    break
                except FuturesTimeoutError:
                    hb += 1
                    yield _sse(
                        "status",
                        {
                            "stage": "running_tools",
                            "message": "Still running retrieval tools",
                            "heartbeat": hb,
                        },
                    )
    except Exception as e:
        logger.exception("run_retrieval_tool_agent failed")
        yield _sse("error", {"message": f"Retrieval tool run failed: {e}"})
        return
    yield _sse(
        "status",
        {
            "stage": "running_tools_complete",
            "message": "Retrieval tools completed",
            "tool_calls": len(tool_state.get("tool_trace") or []),
            "tool_error": bool(tool_agent_err),
        },
    )
    tool_matches = matches_from_tool_state(tool_state, top_k)
    use_tool_matches = bool(not tool_agent_err and len(tool_matches) > 0)

    search_query: str
    pinecone_filter: Optional[dict]
    reasoning: Optional[str]
    plan_err: Optional[str]

    if use_tool_matches:
        search_query = user_query
        pinecone_filter = None
        reasoning = None
        plan_err = None
        payload = {
            "search_query": search_query,
            "pinecone_filter": pinecone_filter,
            "answer_provider": ptype,
            "retrieval_mode": "langchain_tools",
            "tool_trace": tool_state.get("tool_trace") or [],
        }
        yield _sse("plan", payload)

        yield _sse(
            "status",
            {"stage": "embedding", "message": "Embedding search query"},
        )

        yield _sse(
            "status",
            {"stage": "searching_data_source", "message": "Searching your tenant knowledge base"},
        )

        matches = tool_matches
    else:
        if (tool_state.get("tool_trace") or []) and not tool_matches and not tool_agent_err:
            logger.info(
                "Retriever tool agent returned no matches; falling back to legacy planner search."
            )
        if tool_agent_err:
            logger.warning("Retriever tool agent error, using legacy planner: %s", tool_agent_err)

        try:
            with ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(_plan_search, openai_client, user_query, filter_model)
                hb = 0
                while True:
                    try:
                        search_query, pinecone_filter, reasoning, plan_err = fut.result(timeout=1.5)
                        break
                    except FuturesTimeoutError:
                        hb += 1
                        yield _sse(
                            "status",
                            {
                                "stage": "planning_retrieval",
                                "message": "Still planning retrieval query",
                                "heartbeat": hb,
                            },
                        )
        except Exception as e:
            logger.exception("Retriever plan creation failed")
            yield _sse("error", {"message": f"Failed to plan retrieval query: {e}"})
            return
        payload = {
            "search_query": search_query,
            "pinecone_filter": pinecone_filter,
            "answer_provider": ptype,
            "retrieval_mode": "legacy_planner",
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
            with ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(_embed_query, openai_client, search_query, embedding_model)
                hb = 0
                while True:
                    try:
                        vector = fut.result(timeout=1.5)
                        break
                    except FuturesTimeoutError:
                        hb += 1
                        yield _sse(
                            "status",
                            {
                                "stage": "embedding",
                                "message": "Still embedding query",
                                "heartbeat": hb,
                            },
                        )
        except Exception as e:
            logger.exception("Embedding failed")
            yield _sse("error", {"message": f"Embedding failed: {e}"})
            return

        yield _sse(
            "status",
            {"stage": "searching_data_source", "message": "Searching your tenant knowledge base"},
        )

        try:
            yield _sse(
                "status",
                {"stage": "pinecone_query", "message": "Querying vector index"},
            )
            q_kwargs: Dict[str, Any] = {
                "vector": vector,
                "top_k": top_k,
                "include_metadata": True,
                "namespace": namespace,
            }
            if pinecone_filter and isinstance(pinecone_filter, dict) and len(pinecone_filter) > 0:
                q_kwargs["filter"] = pinecone_filter
            with ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(index.query, **q_kwargs)
                hb = 0
                while True:
                    try:
                        raw = fut.result(timeout=1.5)
                        break
                    except FuturesTimeoutError:
                        hb += 1
                        yield _sse(
                            "status",
                            {
                                "stage": "pinecone_query",
                                "message": "Still querying vector index",
                                "heartbeat": hb,
                            },
                        )
        except Exception as e:
            logger.exception("Pinecone query failed")
            yield _sse(
                "error",
                {"message": f"Search failed: {e}"},
            )
            return

        matches = []
        if raw is not None:
            m = getattr(raw, "matches", None)
            if m is None and isinstance(raw, dict):
                m = raw.get("matches")
            matches = list(m) if m else []

    yield _sse(
        "status",
        {
            "stage": "retrieved",
            "message": f"Retrieved {len(matches)} chunk(s) from your tenant store",
            "match_count": len(matches),
        },
    )

    context = _format_matches_for_prompt(matches)

    yield _sse(
        "status",
        {"stage": "generating_response", "message": "Generating answer from retrieved context"},
    )

    system_msg = _strict_language_system_prompt(preferred_language)
    digest = bundle.get("text_digest") or ""
    digest_block = f"User-attached files (extracted text):\n{digest}\n\n" if digest else ""
    user_body = (
        f"Question:\n{user_query}\n\n{digest_block}"
        f"Retrieved context from the knowledge base:\n{context}\n"
    )

    try:
        if ptype == "openai":
            yield _sse(
                "status",
                {
                    "stage": "provider_stream_start",
                    "message": "Starting model response stream",
                    "provider": "openai",
                    "model": answer_model,
                },
            )
            for evt in _stream_openai_chat(
                openai_client,
                answer_model,
                system_msg,
                user_body,
                bundle.get("openai_image_parts") or [],
            ):
                yield evt
        elif ptype == "anthropic":
            if not pkey:
                yield _sse("error", {"message": "Anthropic API key missing."})
                return
            for evt in _stream_anthropic_chat(pkey, answer_model, system_msg, user_body, bundle):
                yield evt
        elif ptype == "mistral":
            if not pkey:
                yield _sse("error", {"message": "Mistral API key missing."})
                return
            yield _sse(
                "status",
                {
                    "stage": "provider_stream_start",
                    "message": "Starting model response stream",
                    "provider": "mistral",
                    "model": answer_model,
                },
            )
            for evt in _stream_mistral_chat(pkey, answer_model, system_msg, user_body):
                yield evt
        else:
            yield _sse("error", {"message": f"Unsupported answer provider: {ptype}"})
            return
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

    **JSON** (default, unchanged):
      ``{"query": "...", "top_k": 8}`` — ``question`` is accepted as an alias for ``query``.

    **Multipart** (optional temporary files, ChatGPT-style):
      - ``query`` or ``question``: text field
      - ``top_k``: optional text field
      - ``file``: one or more file parts (same field name repeated)

    Embeddings and the Pinecone query planner always use the tenant's active **OpenAI**
    row. The streamed answer uses the **most recently updated** active row in
    ``llm_providers`` (openai, anthropic, or mistral).

    SSE events:
      - ``status``, ``plan``, ``token``, ``done``, ``error``

    The ``plan`` event may include ``retrieval_mode`` (``langchain_tools`` or
    ``legacy_planner``) and, for tool retrieval, ``tool_trace`` describing each tool call.
    """
    tenant_id = kwargs["tenant_id"]
    user_id = str((kwargs.get("current_user") or {}).get("id") or "").strip()
    user_query, top_k, attachments = _parse_stream_request()
    if not user_query:
        return jsonify({"error": "query (or question) is required"}), 400

    headers = {
        "Cache-Control": "no-cache, no-transform",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
        "Content-Type": "text/event-stream; charset=utf-8",
    }

    response = Response(
        stream_with_context(_stream_retrieval(tenant_id, user_id, user_query, top_k, attachments)),
        mimetype="text/event-stream",
        headers=headers,
    )
    return response
