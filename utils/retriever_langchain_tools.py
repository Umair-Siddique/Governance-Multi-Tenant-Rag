"""
LangChain StructuredTool definitions for tenant-scoped Pinecone retrieval.

Tools: semantic search (no filter), document search (PDF/DOCX metadata + semantic),
CSV dataset search (CSV file metadata + semantic). Namespace is always the tenant's.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.tools import tool
from langchain_core.utils.function_calling import convert_to_openai_tool

logger = logging.getLogger(__name__)

_RETRIEVAL_AGENT_SYSTEM = """You are a retrieval planner for a tenant knowledge base stored in Pinecone.

Chunks are either from PDF/DOCX (source_type "document", metadata document_id, filename) or from uploaded CSV files (source_type "csv", metadata file_id, filename). Row-level CSV columns are not separate metadata fields; semantic search runs on chunk text that embeds row data.

Choose one or more tools to fetch relevant chunks before an answer is generated. Prefer:
- semantic_search for broad questions across everything.
- search_documents when the user clearly refers to a specific PDF/DOCX (use document_id and/or exact filename if given).
- search_csv_dataset when the user clearly refers to tabular/CSV/spreadsheet data (use file_id and/or exact filename if given).

You may call multiple tools if the question spans sources. Use concise search queries optimized for embeddings."""


def _clamp_top_k(top_k: Optional[int], default: int, hard_max: int = 20) -> int:
    if top_k is None:
        return max(1, min(default, hard_max))
    try:
        v = int(top_k)
    except (TypeError, ValueError):
        v = default
    return max(1, min(v, hard_max))


def _embed_query(openai_client, text: str, embedding_model: str) -> List[float]:
    r = openai_client.embeddings.create(
        model=embedding_model,
        input=(text or "")[:8000],
        dimensions=1536,
    )
    return list(r.data[0].embedding)


def _pinecone_matches(index, namespace: str, vector: List[float], top_k: int, flt: Optional[dict]) -> List[Any]:
    q_kwargs: Dict[str, Any] = {
        "vector": vector,
        "top_k": top_k,
        "include_metadata": True,
        "namespace": namespace,
    }
    if flt and isinstance(flt, dict) and len(flt) > 0:
        q_kwargs["filter"] = flt
    raw = index.query(**q_kwargs)
    if raw is None:
        return []
    m = getattr(raw, "matches", None)
    if m is None and isinstance(raw, dict):
        m = raw.get("matches")
    return list(m) if m else []


def _match_dedupe_key(m: Any) -> str:
    mid = getattr(m, "id", None)
    if mid is not None and str(mid).strip():
        return str(mid)
    meta = getattr(m, "metadata", None) or {}
    if not isinstance(meta, dict):
        meta = {}
    cid = meta.get("chunk_id") or meta.get("document_id") or meta.get("file_id") or ""
    idx = meta.get("chunk_index", "")
    return f"{cid}:{idx}"


def _format_matches_snippet(matches: List[Any], limit_lines: int = 120) -> str:
    parts: List[str] = []
    for i, m in enumerate(matches[:limit_lines], start=1):
        meta = getattr(m, "metadata", None) or {}
        if not isinstance(meta, dict):
            meta = {}
        score = getattr(m, "score", None)
        content = (meta.get("content") or "")[:1200]
        fname = meta.get("filename") or ""
        doc_id = meta.get("document_id") or meta.get("file_id") or ""
        src = meta.get("source_type") or ""
        header = f"[{i}] score={score:.4f}" if score is not None else f"[{i}]"
        parts.append(f"{header} filename={fname} id={doc_id} source={src}\n{content}\n")
    body = "\n---\n".join(parts) if parts else "(no chunks)"
    if len(matches) > limit_lines:
        body += f"\n\n[{len(matches) - limit_lines} more chunk(s) omitted from tool preview]"
    return body


def _merge_matches(into: Dict[str, Any], new_matches: List[Any]) -> None:
    for m in new_matches:
        k = _match_dedupe_key(m)
        if not k or k == ":":
            k = f"anon:{id(m)}"
        prev = into.get(k)
        if prev is None:
            into[k] = m
            continue
        s_new = getattr(m, "score", None)
        s_old = getattr(prev, "score", None)
        if s_new is not None and (s_old is None or s_new > s_old):
            into[k] = m


def build_retrieval_tools(
    openai_client: Any,
    embedding_model: str,
    index: Any,
    namespace: str,
    request_top_k: int,
) -> Tuple[List[Any], Dict[str, Any]]:
    """
    Build LangChain tools bound to the tenant index/namespace. Returns (tools, state)
    where state['matches_by_key'] accumulates all retrieved matches for final RAG context.
    """
    state: Dict[str, Any] = {"matches_by_key": {}, "tool_trace": []}

    default_k = _clamp_top_k(request_top_k, 8)

    def _record(name: str, args: dict, flt: Optional[dict], query: str, matches: List[Any]) -> str:
        state["tool_trace"].append(
            {
                "tool": name,
                "arguments": args,
                "filter": flt,
                "query": query,
                "match_count": len(matches),
            }
        )
        _merge_matches(state["matches_by_key"], matches)
        return _format_matches_snippet(matches)

    @tool
    def semantic_search(query: str, top_k: int = default_k) -> str:
        """Semantic similarity search across all chunks (documents and CSV) with no metadata filter."""
        k = _clamp_top_k(top_k, default_k)
        q = (query or "").strip()
        if not q:
            return "(empty query)"
        try:
            vec = _embed_query(openai_client, q, embedding_model)
            matches = _pinecone_matches(index, namespace, vec, k, None)
        except Exception as e:
            logger.warning("semantic_search failed: %s", e)
            return f"(search error: {e})"
        return _record("semantic_search", {"query": q, "top_k": k}, None, q, matches)

    @tool
    def search_documents(
        query: str,
        top_k: int = default_k,
        document_id: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> str:
        """Semantic search limited to PDF/DOCX chunks (source_type document). Optionally filter by document_id (UUID) and/or exact filename."""
        k = _clamp_top_k(top_k, default_k)
        q = (query or "").strip()
        if not q:
            return "(empty query)"
        doc_id = (document_id or "").strip() or None
        fn = (filename or "").strip() or None
        parts: List[dict] = [{"source_type": {"$eq": "document"}}]
        if doc_id:
            parts.append({"document_id": {"$eq": doc_id}})
        if fn:
            parts.append({"filename": {"$eq": fn}})
        flt: dict = {"$and": parts} if len(parts) > 1 else parts[0]
        try:
            vec = _embed_query(openai_client, q, embedding_model)
            matches = _pinecone_matches(index, namespace, vec, k, flt)
        except Exception as e:
            logger.warning("search_documents failed: %s", e)
            return f"(search error: {e})"
        return _record(
            "search_documents",
            {"query": q, "top_k": k, "document_id": doc_id, "filename": fn},
            flt,
            q,
            matches,
        )

    @tool
    def search_csv_dataset(
        query: str,
        top_k: int = default_k,
        file_id: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> str:
        """Semantic search limited to CSV-derived chunks (source_type csv). Optionally filter by file_id (UUID of the CSV in the catalog) and/or exact filename."""
        k = _clamp_top_k(top_k, default_k)
        q = (query or "").strip()
        if not q:
            return "(empty query)"
        fid = (file_id or "").strip() or None
        fn = (filename or "").strip() or None
        parts: List[dict] = [{"source_type": {"$eq": "csv"}}]
        if fid:
            parts.append({"file_id": {"$eq": fid}})
        if fn:
            parts.append({"filename": {"$eq": fn}})
        flt: dict = {"$and": parts} if len(parts) > 1 else parts[0]
        try:
            vec = _embed_query(openai_client, q, embedding_model)
            matches = _pinecone_matches(index, namespace, vec, k, flt)
        except Exception as e:
            logger.warning("search_csv_dataset failed: %s", e)
            return f"(search error: {e})"
        return _record(
            "search_csv_dataset",
            {"query": q, "top_k": k, "file_id": fid, "filename": fn},
            flt,
            q,
            matches,
        )

    tools = [semantic_search, search_documents, search_csv_dataset]
    return tools, state


def tools_to_openai_functions(tools: List[Any]) -> List[dict]:
    return [convert_to_openai_tool(t) for t in tools]


def run_retrieval_tool_agent(
    openai_client: Any,
    filter_model: str,
    user_query: str,
    tools: List[Any],
    state: Dict[str, Any],
    max_rounds: int = 4,
) -> Tuple[bool, Optional[str]]:
    """
    Run OpenAI tool-calling loop. Mutates ``state`` (matches_by_key, tool_trace).
    Returns (had_any_tool_call, error_message).
    """
    oai_tools = tools_to_openai_functions(tools)
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": _RETRIEVAL_AGENT_SYSTEM},
        {"role": "user", "content": user_query},
    ]
    tool_map = {t.name: t for t in tools}
    had_tool_call = False

    for round_idx in range(max_rounds):
        tool_choice: Any = "required" if round_idx == 0 else "auto"
        try:
            resp = openai_client.chat.completions.create(
                model=filter_model,
                messages=messages,
                tools=oai_tools,
                tool_choice=tool_choice,
                temperature=0.2,
            )
        except Exception as e:
            if round_idx == 0 and tool_choice == "required":
                try:
                    resp = openai_client.chat.completions.create(
                        model=filter_model,
                        messages=messages,
                        tools=oai_tools,
                        tool_choice="auto",
                        temperature=0.2,
                    )
                except Exception as e2:
                    mk = state.get("matches_by_key")
                    if isinstance(mk, dict):
                        mk.clear()
                    tt = state.get("tool_trace")
                    if isinstance(tt, list):
                        tt.clear()
                    return had_tool_call, str(e2)
            else:
                mk = state.get("matches_by_key")
                if isinstance(mk, dict):
                    mk.clear()
                tt = state.get("tool_trace")
                if isinstance(tt, list):
                    tt.clear()
                return had_tool_call, str(e)

        choice = resp.choices[0] if resp.choices else None
        if not choice or not choice.message:
            break

        msg = choice.message
        tcalls = getattr(msg, "tool_calls", None) or []
        if not tcalls:
            if msg.content:
                messages.append({"role": "assistant", "content": msg.content})
            break

        had_tool_call = True
        assistant_payload: Dict[str, Any] = {
            "role": "assistant",
            "content": msg.content or None,
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments or "{}"},
                }
                for tc in tcalls
            ],
        }
        messages.append(assistant_payload)

        for tc in tcalls:
            name = tc.function.name
            raw_args = tc.function.arguments or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except json.JSONDecodeError:
                args = {}
            fn = tool_map.get(name)
            if not fn:
                out = f"(unknown tool: {name})"
            else:
                try:
                    out = fn.invoke(args)
                except Exception as e:
                    logger.warning("Tool %s invoke failed: %s", name, e)
                    out = f"(tool error: {e})"
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": out if isinstance(out, str) else str(out),
                }
            )

    return had_tool_call, None


def matches_from_tool_state(state: Dict[str, Any], cap: int) -> List[Any]:
    """Deduped matches sorted by score descending, capped."""
    by_key: Dict[str, Any] = state.get("matches_by_key") or {}
    items = list(by_key.values())

    def _score(m: Any) -> float:
        s = getattr(m, "score", None)
        try:
            return float(s) if s is not None else float("-inf")
        except (TypeError, ValueError):
            return float("-inf")

    items.sort(key=_score, reverse=True)
    cap = _clamp_top_k(cap, 8)
    return items[:cap]
