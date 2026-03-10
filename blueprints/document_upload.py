"""
Document upload API.
Upload documents → extract text → preprocess → recursive chunk → store in Supabase.
Editor/Admin can upload; reviewers view chunks before approval.
"""
import io
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, request, jsonify, current_app

from utils.auth_helpers import require_role
from utils.document_utils import (
    extract_and_preprocess,
    recursive_chunk,
    is_supported,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_CHUNK_OVERLAP,
)


document_upload_bp = Blueprint("document_upload", __name__)


@document_upload_bp.route("/documents/upload", methods=["POST"])
@require_role("admin", "editor")
def upload_document(**kwargs):
    """
    Upload a document (PDF or DOCX), extract text, preprocess, chunk, and store.

    Expects multipart/form-data with file field "file".

    Returns:
        document_id, filename, status, chunk_count, and chunk IDs for reviewer UI.
    """
    tenant_id = kwargs["tenant_id"]
    current_user = kwargs["current_user"]
    user_id = current_user["id"]

    if "file" not in request.files:
        return jsonify({"error": "No file provided. Use form field 'file'"}), 400

    file = request.files["file"]
    if not file or not file.filename or file.filename.strip() == "":
        return jsonify({"error": "No file selected"}), 400

    filename = file.filename.strip()
    ext = Path(filename).suffix.lower()
    if not is_supported(filename):
        return jsonify({
            "error": f"Unsupported file type: {ext}. Supported: .pdf, .docx"
        }), 400

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    try:
        data = file.read()
        if not data:
            return jsonify({"error": "Empty file"}), 400

        tesseract_cmd = current_app.config.get("TESSERACT_CMD")
        text = extract_and_preprocess(
            io.BytesIO(data),
            file_ext=ext,
            tesseract_cmd=tesseract_cmd,
        )
        if not text or not text.strip():
            return jsonify({
                "error": "Could not extract any text from the document. It may be empty or contain only non-OCR-able content."
            }), 400

        chunks = recursive_chunk(
            text,
            chunk_size=DEFAULT_CHUNK_SIZE,
            chunk_overlap=DEFAULT_CHUNK_OVERLAP,
        )
        if not chunks:
            return jsonify({"error": "No chunks produced after processing"}), 400

        now = datetime.now(timezone.utc).isoformat()
        doc_id = str(uuid.uuid4())

        doc_row = {
            "id": doc_id,
            "tenant_id": tenant_id,
            "filename": filename,
            "file_type": ext.lstrip("."),
            "status": "draft",
            "uploaded_by": user_id,
            "raw_text": text[:100_000] if len(text) > 100_000 else text,
            "chunk_count": len(chunks),
            "created_at": now,
            "updated_at": now,
        }
        supabase.table("documents").insert(doc_row).execute()

        chunk_rows = [
            {
                "document_id": doc_id,
                "tenant_id": tenant_id,
                "chunk_index": i,
                "content": c,
                "char_count": len(c),
            }
            for i, c in enumerate(chunks)
        ]
        supabase.table("document_chunks").insert(chunk_rows).execute()

        return jsonify({
            "document_id": doc_id,
            "filename": filename,
            "status": "draft",
            "chunk_count": len(chunks),
            "chunk_size": DEFAULT_CHUNK_SIZE,
            "chunk_overlap": DEFAULT_CHUNK_OVERLAP,
        }), 201

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        current_app.logger.exception("Document upload failed")
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500


@document_upload_bp.route("/documents", methods=["GET"])
@require_role("admin", "editor", "reviewer")
def list_documents(**kwargs):
    """
    List documents for the tenant. Optional query: ?status=draft|review|approved
    """
    tenant_id = kwargs["tenant_id"]
    status = request.args.get("status", "").strip().lower()

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    cols = "id, tenant_id, filename, file_type, status, uploaded_by, chunk_count, created_at, updated_at"
    q = supabase.table("documents").select(cols).eq("tenant_id", tenant_id).order("created_at", desc=True)
    if status and status in ("draft", "review", "approved"):
        q = q.eq("status", status)

    result = q.execute()
    items = result.data or []
    return jsonify({"documents": items})


@document_upload_bp.route("/documents/<document_id>", methods=["GET"])
@require_role("admin", "editor", "reviewer")
def get_document(document_id: str, **kwargs):
    """
    Get document metadata and its chunks (for reviewer to view all chunks).
    """
    tenant_id = kwargs["tenant_id"]

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    doc_cols = "id, tenant_id, filename, file_type, status, uploaded_by, chunk_count, created_at, updated_at"
    doc_result = supabase.table("documents").select(doc_cols).eq("id", document_id).eq("tenant_id", tenant_id).execute()
    if not doc_result.data:
        return jsonify({"error": "Document not found"}), 404

    doc = doc_result.data[0]
    chunks_result = (
        supabase.table("document_chunks")
        .select("id, chunk_index, content, char_count")
        .eq("document_id", document_id)
        .eq("tenant_id", tenant_id)
        .order("chunk_index")
        .execute()
    )
    chunks = chunks_result.data or []

    return jsonify({
        "document": doc,
        "chunks": chunks,
    })


@document_upload_bp.route("/documents/publish-to-pinecone", methods=["POST"])
@require_role("admin", "editor")
def publish_to_pinecone(**kwargs):
    """
    Reviewer API: Embed approved document chunks using text-embedding-3-small (1536 dims)
    and store in the tenant's Pinecone index.
    Optional body: { "document_ids": ["uuid1", ...] } - if empty/omitted, publish all approved docs.
    """
    tenant_id = kwargs["tenant_id"]

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    pinecone_service = getattr(current_app, "pinecone_service", None)
    if not pinecone_service:
        return jsonify({"error": "Pinecone not configured"}), 500

    openai_client = getattr(current_app, "openai_service", None)
    if not openai_client:
        return jsonify({"error": "OpenAI not configured"}), 500

    body = request.get_json(silent=True) or {}
    document_ids = body.get("document_ids") or []

    # Resolve documents to publish: specific IDs or all approved
    if document_ids:
        doc_result = (
            supabase.table("documents")
            .select("id, filename")
            .eq("tenant_id", tenant_id)
            .eq("status", "approved")
            .in_("id", document_ids)
            .execute()
        )
    else:
        doc_result = (
            supabase.table("documents")
            .select("id, filename")
            .eq("tenant_id", tenant_id)
            .eq("status", "approved")
            .execute()
        )

    docs = doc_result.data or []
    if not docs:
        return jsonify({
            "message": "No approved documents to publish",
            "documents_published": 0,
            "chunks_upserted": 0,
        }), 200

    doc_ids = [d["id"] for d in docs]
    doc_filenames = {d["id"]: d["filename"] for d in docs}

    # Fetch chunks for these documents
    chunks_result = (
        supabase.table("document_chunks")
        .select("id, document_id, chunk_index, content")
        .eq("tenant_id", tenant_id)
        .in_("document_id", doc_ids)
        .order("document_id")
        .order("chunk_index")
        .execute()
    )
    chunks = chunks_result.data or []
    if not chunks:
        return jsonify({
            "message": "No chunks found for approved documents",
            "documents_published": 0,
            "chunks_upserted": 0,
        }), 200

    # Batch embed with OpenAI text-embedding-3-small (1536 dimensions)
    texts = [c["content"] for c in chunks]
    batch_size = 100
    all_embeddings = []

    for i in range(0, len(texts), batch_size):
        batch_texts = texts[i : i + batch_size]
        resp = openai_client.embeddings.create(
            model="text-embedding-3-small",
            input=batch_texts,
            dimensions=1536,
        )
        all_embeddings.extend([e.embedding for e in resp.data])

    # Build vectors with metadata
    vectors = []
    for chunk, embedding in zip(chunks, all_embeddings):
        chunk_id = chunk["id"]
        document_id = chunk["document_id"]
        filename = doc_filenames.get(document_id, "")
        vectors.append({
            "id": str(chunk_id),
            "values": embedding,
            "metadata": {
                "tenant_id": str(tenant_id),
                "document_id": str(document_id),
                "chunk_id": str(chunk_id),
                "chunk_index": int(chunk["chunk_index"]),
                "filename": str(filename),
                "content": str(chunk["content"])[:10000],  # Pinecone metadata ~40KB limit
            },
        })

    pinecone_service.upsert_vectors(tenant_id, vectors)

    return jsonify({
        "message": "Documents published to vector store",
        "documents_published": len(docs),
        "chunks_upserted": len(vectors),
    }), 200
