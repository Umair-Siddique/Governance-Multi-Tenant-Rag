"""
Document upload API.
Upload documents → extract text → preprocess → recursive chunk → store in Supabase.
CSV: Supabase as Metadata Catalog (csv_registry + csv_chunks), Pinecone as Search Index with metadata bridge.
Editor/Admin can upload; reviewers view chunks before approval.

All processing is done via Celery background tasks.
Documents are stored in Supabase Storage and processed in bulk.
"""
import uuid
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, request, jsonify, current_app

from utils.auth_helpers import require_role
from utils.document_utils import (
    is_supported,
)


document_upload_bp = Blueprint("document_upload", __name__)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for Supabase Storage.
    Removes/replaces special characters, spaces, and ensures safe path format.
    """
    # Get the base name and extension
    path_obj = Path(filename)
    base_name = path_obj.stem
    extension = path_obj.suffix
    
    # Normalize unicode (e.g., ñ -> n)
    base_name = unicodedata.normalize('NFKD', base_name)
    base_name = base_name.encode('ascii', 'ignore').decode('ascii')
    
    # Replace spaces and special characters with underscores
    base_name = re.sub(r'[^\w\-]', '_', base_name)
    # Remove multiple consecutive underscores
    base_name = re.sub(r'_+', '_', base_name)
    # Remove leading/trailing underscores
    base_name = base_name.strip('_')
    
    # If base_name is empty after sanitization, use a default
    if not base_name:
        base_name = "document"
    
    return f"{base_name}{extension}"


@document_upload_bp.route("/tasks/<task_id>", methods=["GET"])
@require_role("admin", "editor", "reviewer")
def get_task_status(task_id: str, **kwargs):
    """
    Get the status of a Celery task.
    
    Returns:
        task_id, status (PENDING, STARTED, SUCCESS, FAILURE), result (if completed), error (if failed)
    """
    celery_app = current_app.celery
    task = celery_app.AsyncResult(task_id)
    
    if task.state == 'PENDING':
        response = {
            'task_id': task_id,
            'status': 'PENDING',
            'message': 'Task is waiting to be processed',
        }
    elif task.state == 'STARTED':
        response = {
            'task_id': task_id,
            'status': 'PROCESSING',
            'message': 'Task is being processed',
        }
    elif task.state == 'SUCCESS':
        response = {
            'task_id': task_id,
            'status': 'SUCCESS',
            'result': task.result,
        }
    elif task.state == 'FAILURE':
        response = {
            'task_id': task_id,
            'status': 'FAILURE',
            'error': str(task.info),
        }
    else:
        response = {
            'task_id': task_id,
            'status': task.state,
            'result': task.result if task.ready() else None,
        }
    
    return jsonify(response), 200


@document_upload_bp.route("/documents/upload", methods=["POST"])
@require_role("admin", "editor")
def upload_document(**kwargs):
    """
    Upload one or more documents (PDF, DOCX, CSV), store in Supabase Storage, and queue for processing.
    Supports bulk uploads - accepts multiple files in a single request.

    Expects multipart/form-data with file field "file" (can be multiple files).

    Returns:
        List of uploaded documents with their document_ids, task_ids, and status.
    """
    tenant_id = kwargs["tenant_id"]
    current_user = kwargs["current_user"]
    user_id = current_user["id"]

    if "file" not in request.files:
        return jsonify({"error": "No file provided. Use form field 'file'"}), 400

    # Get all files (supports both single and multiple file uploads)
    files = request.files.getlist("file")
    if not files or all(not f or not f.filename or f.filename.strip() == "" for f in files):
        return jsonify({"error": "No files selected"}), 400

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    uploaded_documents = []
    errors = []

    for file in files:
        if not file or not file.filename or file.filename.strip() == "":
            continue

        try:
            filename = file.filename.strip()
            ext = Path(filename).suffix.lower()
            
            if not is_supported(filename):
                errors.append({
                    "filename": filename,
                    "error": f"Unsupported file type: {ext}. Supported: .pdf, .docx, .csv"
                })
                continue

            data = file.read()
            if not data:
                errors.append({
                    "filename": filename,
                    "error": "Empty file"
                })
                continue

            # Generate unique storage path with sanitized filename
            storage_id = str(uuid.uuid4())
            sanitized_filename = sanitize_filename(filename)
            storage_path = f"{tenant_id}/{storage_id}_{sanitized_filename}"
            
            # Upload to Supabase Storage bucket "elorag-docs"
            try:
                storage_response = supabase.storage.from_("elorag-docs").upload(
                    storage_path,
                    data,
                    file_options={"content-type": file.content_type or "application/octet-stream"}
                )
                
                if not storage_response:
                    errors.append({
                        "filename": filename,
                        "error": "Failed to upload file to storage"
                    })
                    continue
            except Exception as e:
                current_app.logger.exception(f"Storage upload failed for {filename}")
                errors.append({
                    "filename": filename,
                    "error": f"Storage upload failed: {str(e)}"
                })
                continue

            # Create database record with pending_processing status
            now = datetime.now(timezone.utc).isoformat()
            doc_id = str(uuid.uuid4())
            
            # For CSV, use csv_registry table
            if ext == ".csv":
                registry_row = {
                    "id": doc_id,
                    "tenant_id": tenant_id,
                    "filename": filename,
                    "columns": [],  # Will be populated during processing
                    "status": "pending_processing",
                    "uploaded_by": user_id,
                    "storage_path": storage_path,
                    "row_count": 0,
                    "chunk_count": 0,
                    "created_at": now,
                    "updated_at": now,
                }
                supabase.table("csv_registry").insert(registry_row).execute()
                
                # Enqueue processing task
                from tasks.document_tasks import process_document_from_storage
                task = process_document_from_storage.delay(
                    tenant_id=tenant_id,
                    document_id=doc_id,
                    storage_path=storage_path,
                    filename=filename,
                    file_type="csv",
                )
            else:
                # For PDF/DOCX, use documents table
                doc_row = {
                    "id": doc_id,
                    "tenant_id": tenant_id,
                    "filename": filename,
                    "file_type": ext.lstrip("."),
                    "status": "pending_processing",
                    "uploaded_by": user_id,
                    "storage_path": storage_path,
                    "chunk_count": 0,
                    "created_at": now,
                    "updated_at": now,
                }
                supabase.table("documents").insert(doc_row).execute()
                
                # Enqueue processing task
                from tasks.document_tasks import process_document_from_storage
                task = process_document_from_storage.delay(
                    tenant_id=tenant_id,
                    document_id=doc_id,
                    storage_path=storage_path,
                    filename=filename,
                    file_type=ext.lstrip("."),
                )
            
            uploaded_documents.append({
                "document_id": doc_id,
                "task_id": task.id,
                "filename": filename,
                "status": "pending_processing",
            })

        except Exception as e:
            current_app.logger.exception(f"Error processing file {file.filename if file else 'unknown'}")
            errors.append({
                "filename": file.filename if file else "unknown",
                "error": f"Upload failed: {str(e)}"
            })
            continue

    # Return response with all uploaded documents and any errors
    response = {
        "message": f"Uploaded {len(uploaded_documents)} document(s) to storage and queued for processing",
        "uploaded": uploaded_documents,
        "total_uploaded": len(uploaded_documents),
    }
    
    if errors:
        response["errors"] = errors
        response["total_errors"] = len(errors)
    
    # Return 207 Multi-Status if there are mixed results, 202 if all succeeded, 400 if all failed
    if errors and not uploaded_documents:
        return jsonify(response), 400
    elif errors:
        return jsonify(response), 207  # Multi-Status
    else:
        return jsonify(response), 202




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


@document_upload_bp.route("/documents/bulk-approve", methods=["POST"])
@require_role("admin", "reviewer")
def bulk_approve_documents(**kwargs):
    """
    Bulk approve documents. Reviewer can approve documents from draft status.
    
    Request body:
    {
        "document_ids": ["uuid1", "uuid2", ...]  # Optional: if empty, approves all draft documents
    }
    
    Returns:
        Count of approved documents and list of approved IDs.
    """
    tenant_id = kwargs["tenant_id"]
    current_user = kwargs["current_user"]
    user_id = current_user["id"]
    
    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500
    
    body = request.get_json(silent=True) or {}
    document_ids = body.get("document_ids") or []
    
    now = datetime.now(timezone.utc).isoformat()
    
    # Build query for documents to approve
    if document_ids:
        # Approve specific documents (must be in draft or review status)
        q = (
            supabase.table("documents")
            .update({
                "status": "approved",
                "updated_at": now,
            })
            .eq("tenant_id", tenant_id)
            .in_("id", document_ids)
            .in_("status", ["draft", "review"])
        )
    else:
        # Approve all draft documents for the tenant
        q = (
            supabase.table("documents")
            .update({
                "status": "approved",
                "updated_at": now,
            })
            .eq("tenant_id", tenant_id)
            .eq("status", "draft")
        )
    
    result = q.execute()
    approved_count = len(result.data) if result.data else 0
    approved_ids = [doc["id"] for doc in result.data] if result.data else []
    
    return jsonify({
        "message": f"Approved {approved_count} document(s)",
        "approved_count": approved_count,
        "approved_document_ids": approved_ids,
        "action": "bulk_approve",
        "actor": user_id,
        "timestamp": now,
    }), 200


@document_upload_bp.route("/documents/bulk-reject", methods=["POST"])
@require_role("admin", "reviewer")
def bulk_reject_documents(**kwargs):
    """
    Bulk reject documents. Rejects documents by deleting them or marking as rejected.
    For now, we'll delete rejected documents as per governance requirements.
    
    Request body:
    {
        "document_ids": ["uuid1", "uuid2", ...]  # Required: list of document IDs to reject
    }
    
    Returns:
        Count of rejected documents and list of rejected IDs.
    """
    tenant_id = kwargs["tenant_id"]
    current_user = kwargs["current_user"]
    user_id = current_user["id"]
    
    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500
    
    body = request.get_json(silent=True) or {}
    document_ids = body.get("document_ids") or []
    
    if not document_ids:
        return jsonify({"error": "document_ids is required"}), 400
    
    now = datetime.now(timezone.utc).isoformat()
    
    # Get documents before deletion for audit
    docs_to_delete = (
        supabase.table("documents")
        .select("id, filename")
        .eq("tenant_id", tenant_id)
        .in_("id", document_ids)
        .execute()
    )
    
    rejected_ids = [doc["id"] for doc in docs_to_delete.data] if docs_to_delete.data else []
    
    # Delete documents (cascade will delete chunks automatically)
    if rejected_ids:
        delete_result = (
            supabase.table("documents")
            .delete()
            .eq("tenant_id", tenant_id)
            .in_("id", rejected_ids)
            .execute()
        )
    
    rejected_count = len(rejected_ids)
    
    return jsonify({
        "message": f"Rejected {rejected_count} document(s)",
        "rejected_count": rejected_count,
        "rejected_document_ids": rejected_ids,
        "action": "bulk_reject",
        "actor": user_id,
        "timestamp": now,
    }), 200


@document_upload_bp.route("/documents/<document_id>/status", methods=["PATCH"])
@require_role("admin", "reviewer")
def update_document_status(document_id: str, **kwargs):
    """Update single document status (draft | review | approved)."""
    tenant_id = kwargs["tenant_id"]
    body = request.get_json(silent=True) or {}
    status = (body.get("status") or "").strip().lower()
    if status not in ("draft", "review", "approved"):
        return jsonify({"error": "status must be draft, review, or approved"}), 400
    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500
    result = supabase.table("documents").update({
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", document_id).eq("tenant_id", tenant_id).execute()
    if not result.data:
        return jsonify({"error": "Document not found"}), 404
    return jsonify({"document_id": document_id, "status": status}), 200


@document_upload_bp.route("/documents/publish-to-pinecone", methods=["POST"])
@require_role("admin", "editor")
def publish_to_pinecone(**kwargs):
    """
    Publish approved content to Pinecone: both documents (PDF/DOCX) and CSV files.
    Optional body: { "document_ids": ["uuid1", ...], "file_ids": ["uuid2", ...] }.
    If document_ids omitted/empty, all approved documents are included.
    If file_ids omitted/empty, all approved CSV files are included.
    One call publishes both types so a single "Publish to Pinecone" action works for CSV too.
    
    Returns task_id for background processing.
    """
    tenant_id = kwargs["tenant_id"]
    
    body = request.get_json(silent=True) or {}
    document_ids = body.get("document_ids") or []
    file_ids = body.get("file_ids") or []

    # Enqueue background task
    from tasks.document_tasks import publish_to_pinecone_task
    task = publish_to_pinecone_task.delay(
        tenant_id=tenant_id,
        document_ids=document_ids if document_ids else None,
        file_ids=file_ids if file_ids else None,
    )
    
    return jsonify({
        "message": "Publish to Pinecone queued for processing",
        "task_id": task.id,
        "status": "processing",
    }), 202


# --- CSV Registry (Metadata Catalog) + Pinecone bridge ---

@document_upload_bp.route("/csv-registry", methods=["GET"])
@require_role("admin", "editor", "reviewer")
def list_csv_registry(**kwargs):
    """List CSV files for the tenant. Optional query: ?status=draft|review|approved"""
    tenant_id = kwargs["tenant_id"]
    status = request.args.get("status", "").strip().lower()

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    cols = "id, tenant_id, filename, columns, summary, status, uploaded_by, row_count, chunk_count, created_at, updated_at"
    q = supabase.table("csv_registry").select(cols).eq("tenant_id", tenant_id).order("created_at", desc=True)
    if status and status in ("draft", "review", "approved"):
        q = q.eq("status", status)
    result = q.execute()
    items = result.data or []
    return jsonify({"csv_files": items})


@document_upload_bp.route("/csv-registry/<file_id>", methods=["GET"])
@require_role("admin", "editor", "reviewer")
def get_csv_file(file_id: str, **kwargs):
    """Get one CSV file metadata and its chunks (for reviewer)."""
    tenant_id = kwargs["tenant_id"]
    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    reg = supabase.table("csv_registry").select("*").eq("id", file_id).eq("tenant_id", tenant_id).execute()
    if not reg.data:
        return jsonify({"error": "CSV file not found"}), 404
    file_meta = reg.data[0]
    chunks_result = (
        supabase.table("csv_chunks")
        .select("id, chunk_index, content, char_count")
        .eq("csv_file_id", file_id)
        .eq("tenant_id", tenant_id)
        .order("chunk_index")
        .execute()
    )
    chunks = chunks_result.data or []
    return jsonify({"csv_file": file_meta, "chunks": chunks})


@document_upload_bp.route("/csv-registry/bulk-approve", methods=["POST"])
@require_role("admin", "reviewer")
def bulk_approve_csv(**kwargs):
    """
    Bulk approve CSV files. Reviewer can approve CSV files from draft status.
    
    Request body:
    {
        "file_ids": ["uuid1", "uuid2", ...]  # Optional: if empty, approves all draft CSV files
    }
    
    Returns:
        Count of approved CSV files and list of approved IDs.
    """
    tenant_id = kwargs["tenant_id"]
    current_user = kwargs["current_user"]
    user_id = current_user["id"]
    
    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500
    
    body = request.get_json(silent=True) or {}
    file_ids = body.get("file_ids") or []
    
    now = datetime.now(timezone.utc).isoformat()
    
    # Build query for CSV files to approve
    if file_ids:
        # Approve specific CSV files (must be in draft or review status)
        q = (
            supabase.table("csv_registry")
            .update({
                "status": "approved",
                "updated_at": now,
            })
            .eq("tenant_id", tenant_id)
            .in_("id", file_ids)
            .in_("status", ["draft", "review"])
        )
    else:
        # Approve all draft CSV files for the tenant
        q = (
            supabase.table("csv_registry")
            .update({
                "status": "approved",
                "updated_at": now,
            })
            .eq("tenant_id", tenant_id)
            .eq("status", "draft")
        )
    
    result = q.execute()
    approved_count = len(result.data) if result.data else 0
    approved_ids = [f["id"] for f in result.data] if result.data else []
    
    return jsonify({
        "message": f"Approved {approved_count} CSV file(s)",
        "approved_count": approved_count,
        "approved_file_ids": approved_ids,
        "action": "bulk_approve",
        "actor": user_id,
        "timestamp": now,
    }), 200


@document_upload_bp.route("/csv-registry/bulk-reject", methods=["POST"])
@require_role("admin", "reviewer")
def bulk_reject_csv(**kwargs):
    """
    Bulk reject CSV files. Rejects CSV files by deleting them.
    
    Request body:
    {
        "file_ids": ["uuid1", "uuid2", ...]  # Required: list of CSV file IDs to reject
    }
    
    Returns:
        Count of rejected CSV files and list of rejected IDs.
    """
    tenant_id = kwargs["tenant_id"]
    current_user = kwargs["current_user"]
    user_id = current_user["id"]
    
    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500
    
    body = request.get_json(silent=True) or {}
    file_ids = body.get("file_ids") or []
    
    if not file_ids:
        return jsonify({"error": "file_ids is required"}), 400
    
    now = datetime.now(timezone.utc).isoformat()
    
    # Get CSV files before deletion for audit
    files_to_delete = (
        supabase.table("csv_registry")
        .select("id, filename")
        .eq("tenant_id", tenant_id)
        .in_("id", file_ids)
        .execute()
    )
    
    rejected_ids = [f["id"] for f in files_to_delete.data] if files_to_delete.data else []
    
    # Delete CSV files (cascade will delete chunks automatically)
    if rejected_ids:
        delete_result = (
            supabase.table("csv_registry")
            .delete()
            .eq("tenant_id", tenant_id)
            .in_("id", rejected_ids)
            .execute()
        )
    
    rejected_count = len(rejected_ids)
    
    return jsonify({
        "message": f"Rejected {rejected_count} CSV file(s)",
        "rejected_count": rejected_count,
        "rejected_file_ids": rejected_ids,
        "action": "bulk_reject",
        "actor": user_id,
        "timestamp": now,
    }), 200


@document_upload_bp.route("/csv-registry/<file_id>/status", methods=["PATCH"])
@require_role("admin", "reviewer")
def update_csv_status(file_id: str, **kwargs):
    """Update single CSV file status (draft | review | approved)."""
    tenant_id = kwargs["tenant_id"]
    body = request.get_json(silent=True) or {}
    status = (body.get("status") or "").strip().lower()
    if status not in ("draft", "review", "approved"):
        return jsonify({"error": "status must be draft, review, or approved"}), 400
    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500
    result = supabase.table("csv_registry").update({
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", file_id).eq("tenant_id", tenant_id).execute()
    if not result.data:
        return jsonify({"error": "CSV file not found"}), 404
    return jsonify({"file_id": file_id, "status": status}), 200


@document_upload_bp.route("/csv-registry/publish-to-pinecone", methods=["POST"])
@require_role("admin", "editor")
def publish_csv_to_pinecone(**kwargs):
    """
    Embed approved CSV chunks and upsert to tenant Pinecone index.
    Metadata includes file_id and source_type='csv' to bridge with Supabase csv_registry.
    Optional body: { "file_ids": ["uuid1", ...] } — if empty, publish all approved CSV files.
    
    Returns task_id for background processing.
    """
    tenant_id = kwargs["tenant_id"]
    
    body = request.get_json(silent=True) or {}
    file_ids = body.get("file_ids") or []

    # Enqueue background task (only CSV files, no documents)
    from tasks.document_tasks import publish_to_pinecone_task
    task = publish_to_pinecone_task.delay(
        tenant_id=tenant_id,
        document_ids=None,  # Only CSV files
        file_ids=file_ids if file_ids else None,
    )
    
    return jsonify({
        "message": "CSV publish to Pinecone queued for processing",
        "task_id": task.id,
        "status": "processing",
    }), 202
