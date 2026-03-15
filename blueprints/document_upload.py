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
    # Use the same Celery instance that creates the tasks (from tasks.document_tasks)
    from tasks.document_tasks import celery as task_celery
    
    # Fallback to app.celery if task_celery is not initialized
    celery_app = task_celery if task_celery is not None else current_app.celery
    
    if not celery_app:
        return jsonify({
            'task_id': task_id,
            'status': 'ERROR',
            'error': 'Celery not initialized'
        }), 500
    
    task = celery_app.AsyncResult(task_id)
    
    # Get task state and info
    task_state = task.state
    task_ready = task.ready()
    
    if task_state == 'PENDING':
        # Check if task is actually pending or if result backend lost it
        if task_ready:
            # Task completed but result might be expired
            try:
                result = task.result
                response = {
                    'task_id': task_id,
                    'status': 'SUCCESS',
                    'result': result,
                    'message': 'Task completed (result retrieved from cache)',
                }
            except Exception as e:
                response = {
                    'task_id': task_id,
                    'status': 'PENDING',
                    'message': 'Task is waiting to be processed or result expired',
                }
        else:
            response = {
                'task_id': task_id,
                'status': 'PENDING',
                'message': 'Task is waiting to be processed',
            }
    elif task_state == 'STARTED':
        response = {
            'task_id': task_id,
            'status': 'PROCESSING',
            'message': 'Task is being processed',
        }
    elif task_state == 'SUCCESS':
        try:
            result = task.result
            response = {
                'task_id': task_id,
                'status': 'SUCCESS',
                'result': result,
            }
        except Exception as e:
            response = {
                'task_id': task_id,
                'status': 'SUCCESS',
                'message': 'Task completed but result unavailable',
                'error': str(e),
            }
    elif task_state == 'FAILURE':
        try:
            error_info = task.info
            response = {
                'task_id': task_id,
                'status': 'FAILURE',
                'error': str(error_info) if error_info else 'Task failed',
            }
        except Exception as e:
            response = {
                'task_id': task_id,
                'status': 'FAILURE',
                'error': f'Task failed: {str(e)}',
            }
    else:
        # Handle other states (RETRY, REVOKED, etc.)
        try:
            result = task.result if task_ready else None
            response = {
                'task_id': task_id,
                'status': task_state,
                'result': result,
                'message': f'Task state: {task_state}',
            }
        except Exception as e:
            response = {
                'task_id': task_id,
                'status': task_state,
                'message': f'Task state: {task_state}',
                'error': str(e),
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
    batch_items = []          # items to hand to the single batch task
    errors = []

    now = datetime.now(timezone.utc).isoformat()

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
            doc_id = str(uuid.uuid4())
            file_type = "csv" if ext == ".csv" else ext.lstrip(".")

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
            else:
                # For PDF/DOCX, use documents table
                doc_row = {
                    "id": doc_id,
                    "tenant_id": tenant_id,
                    "filename": filename,
                    "file_type": file_type,
                    "status": "pending_processing",
                    "uploaded_by": user_id,
                    "storage_path": storage_path,
                    "chunk_count": 0,
                    "created_at": now,
                    "updated_at": now,
                }
                supabase.table("documents").insert(doc_row).execute()

            uploaded_documents.append({
                "document_id": doc_id,
                "filename": filename,
                "file_type": file_type,
                "status": "pending_processing",
            })
            batch_items.append({
                "document_id": doc_id,
                "storage_path": storage_path,
                "filename": filename,
                "file_type": file_type,
            })

        except Exception as e:
            current_app.logger.exception(f"Error processing file {file.filename if file else 'unknown'}")
            errors.append({
                "filename": file.filename if file else "unknown",
                "error": f"Upload failed: {str(e)}"
            })
            continue

    # Dispatch ONE batch task for all successfully uploaded documents
    batch_task_id = None
    if batch_items:
        from tasks.document_tasks import process_document_batch
        batch_task = process_document_batch.delay(
            tenant_id=tenant_id,
            batch_items=batch_items,
        )
        batch_task_id = batch_task.id

    # Return response with all uploaded documents and any errors
    response = {
        "message": f"Uploaded {len(uploaded_documents)} document(s) to storage and queued for processing",
        "batch_task_id": batch_task_id,
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
    List all documents (PDF/DOCX) and CSV files for the tenant, combined.
    Optional query: ?status=draft|review|approved|rejected|pending_processing|processing_failed
    """
    tenant_id = kwargs["tenant_id"]
    status = request.args.get("status", "").strip().lower()

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    valid_statuses = ("draft", "review", "approved", "rejected", "pending_processing", "processing_failed")

    # Query documents table (PDF/DOCX)
    doc_cols = "id, tenant_id, filename, file_type, status, uploaded_by, chunk_count, rejection_reason, created_at, updated_at"
    doc_q = supabase.table("documents").select(doc_cols).eq("tenant_id", tenant_id)
    if status and status in valid_statuses:
        doc_q = doc_q.eq("status", status)
    doc_result = doc_q.execute()
    doc_items = doc_result.data or []

    # Query csv_registry table (CSV) — normalise to same shape
    csv_cols = "id, tenant_id, filename, status, uploaded_by, chunk_count, rejection_reason, created_at, updated_at"
    csv_q = supabase.table("csv_registry").select(csv_cols).eq("tenant_id", tenant_id)
    if status and status in valid_statuses:
        csv_q = csv_q.eq("status", status)
    csv_result = csv_q.execute()
    csv_items = csv_result.data or []

    # Tag CSV rows with file_type so the caller can tell them apart
    for item in csv_items:
        item.setdefault("file_type", "csv")

    # Merge and sort by created_at descending
    all_items = doc_items + csv_items
    all_items.sort(key=lambda x: x.get("created_at") or "", reverse=True)

    return jsonify({"documents": all_items})


@document_upload_bp.route("/documents/<document_id>", methods=["GET"])
@require_role("admin", "editor", "reviewer")
def get_document(document_id: str, **kwargs):
    """
    Get document metadata and its chunks.
    Checks documents table first (PDF/DOCX), then csv_registry (CSV).
    """
    tenant_id = kwargs["tenant_id"]

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    # --- Try documents table first (PDF / DOCX) ---
    doc_cols = "id, tenant_id, filename, file_type, status, uploaded_by, chunk_count, rejection_reason, created_at, updated_at"
    doc_result = supabase.table("documents").select(doc_cols).eq("id", document_id).eq("tenant_id", tenant_id).execute()
    if doc_result.data:
        doc = doc_result.data[0]
        chunks_result = (
            supabase.table("document_chunks")
            .select("id, chunk_index, content, char_count")
            .eq("document_id", document_id)
            .eq("tenant_id", tenant_id)
            .order("chunk_index")
            .execute()
        )
        return jsonify({
            "document": doc,
            "chunks": chunks_result.data or [],
        })

    # --- Fall back to csv_registry (CSV) ---
    csv_cols = "id, tenant_id, filename, status, uploaded_by, chunk_count, rejection_reason, created_at, updated_at"
    csv_result = supabase.table("csv_registry").select(csv_cols).eq("id", document_id).eq("tenant_id", tenant_id).execute()
    if not csv_result.data:
        return jsonify({"error": "Document not found"}), 404

    csv_file = csv_result.data[0]
    csv_file.setdefault("file_type", "csv")
    chunks_result = (
        supabase.table("csv_chunks")
        .select("id, chunk_index, content, char_count")
        .eq("csv_file_id", document_id)
        .eq("tenant_id", tenant_id)
        .order("chunk_index")
        .execute()
    )
    return jsonify({
        "document": csv_file,
        "chunks": chunks_result.data or [],
    })


@document_upload_bp.route("/documents/bulk-approve", methods=["POST"])
@require_role("admin", "reviewer")
def bulk_approve_documents(**kwargs):
    """
    Bulk approve documents (PDF/DOCX) and/or CSV files.
    Pass a mixed list of IDs — each ID is matched against documents first,
    then csv_registry. All-IDs-empty approves every draft in both tables.

    Request body:
    {
        "document_ids": ["uuid1", "uuid2", ...]  # Optional: if empty, approves all draft docs+csvs
    }
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
    approve_payload = {"status": "approved", "updated_at": now}

    if document_ids:
        # Determine which IDs belong to documents vs csv_registry
        doc_check = supabase.table("documents").select("id").eq("tenant_id", tenant_id).in_("id", document_ids).execute()
        doc_ids_in_docs = {r["id"] for r in (doc_check.data or [])}
        csv_ids = [i for i in document_ids if i not in doc_ids_in_docs]

        # Approve matched document IDs
        doc_result = (
            supabase.table("documents")
            .update(approve_payload)
            .eq("tenant_id", tenant_id)
            .in_("id", list(doc_ids_in_docs))
            .in_("status", ["draft", "review"])
            .execute()
        ) if doc_ids_in_docs else None

        # Approve matched CSV IDs
        csv_result = (
            supabase.table("csv_registry")
            .update(approve_payload)
            .eq("tenant_id", tenant_id)
            .in_("id", csv_ids)
            .in_("status", ["draft", "review"])
            .execute()
        ) if csv_ids else None
    else:
        # Approve ALL draft items in both tables
        doc_result = (
            supabase.table("documents")
            .update(approve_payload)
            .eq("tenant_id", tenant_id)
            .eq("status", "draft")
            .execute()
        )
        csv_result = (
            supabase.table("csv_registry")
            .update(approve_payload)
            .eq("tenant_id", tenant_id)
            .eq("status", "draft")
            .execute()
        )

    approved_doc_ids = [r["id"] for r in (doc_result.data if doc_result else [])]
    approved_csv_ids = [r["id"] for r in (csv_result.data if csv_result else [])]
    approved_ids = approved_doc_ids + approved_csv_ids

    return jsonify({
        "message": f"Approved {len(approved_ids)} document(s)",
        "approved_count": len(approved_ids),
        "approved_document_ids": approved_ids,
        "action": "bulk_approve",
        "actor": user_id,
        "timestamp": now,
    }), 200


@document_upload_bp.route("/documents/bulk-reject", methods=["POST"])
@require_role("admin", "reviewer")
def bulk_reject_documents(**kwargs):
    """
    Bulk reject documents (PDF/DOCX) and/or CSV files.
    Pass a mixed list of IDs — each ID is matched against documents first,
    then csv_registry. Marks them as 'rejected' and stores the rejection reason.

    Request body:
    {
        "document_ids": ["uuid1", "uuid2", ...],  # Required
        "reason": "Optional rejection reason"
    }
    """
    tenant_id = kwargs["tenant_id"]
    current_user = kwargs["current_user"]
    user_id = current_user["id"]

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    body = request.get_json(silent=True) or {}
    document_ids = body.get("document_ids") or []
    reason = (body.get("reason") or "").strip()

    if not document_ids:
        return jsonify({"error": "document_ids is required"}), 400

    now = datetime.now(timezone.utc).isoformat()
    reject_payload = {
        "status": "rejected",
        "rejection_reason": reason or None,
        "updated_at": now,
    }

    # Determine which IDs belong to documents vs csv_registry
    doc_check = supabase.table("documents").select("id").eq("tenant_id", tenant_id).in_("id", document_ids).execute()
    doc_ids_in_docs = {r["id"] for r in (doc_check.data or [])}
    csv_ids = [i for i in document_ids if i not in doc_ids_in_docs]

    # Reject matched document IDs
    doc_result = (
        supabase.table("documents")
        .update(reject_payload)
        .eq("tenant_id", tenant_id)
        .in_("id", list(doc_ids_in_docs))
        .execute()
    ) if doc_ids_in_docs else None

    # Reject matched CSV IDs
    csv_result = (
        supabase.table("csv_registry")
        .update(reject_payload)
        .eq("tenant_id", tenant_id)
        .in_("id", csv_ids)
        .execute()
    ) if csv_ids else None

    rejected_doc_ids = [r["id"] for r in (doc_result.data if doc_result else [])]
    rejected_csv_ids = [r["id"] for r in (csv_result.data if csv_result else [])]
    rejected_ids = rejected_doc_ids + rejected_csv_ids

    response = {
        "message": f"Rejected {len(rejected_ids)} document(s)",
        "rejected_count": len(rejected_ids),
        "rejected_document_ids": rejected_ids,
        "action": "bulk_reject",
        "actor": user_id,
        "timestamp": now,
    }
    if reason:
        response["reason"] = reason

    return jsonify(response), 200


@document_upload_bp.route("/documents/<document_id>", methods=["DELETE"])
@require_role("admin", "editor")
def delete_document(document_id: str, **kwargs):
    """
    Delete a document (PDF/DOCX) or CSV file and all associated data.
    Checks documents table first; if not found, checks csv_registry.
    Deletes: DB record, chunks (cascade), and file from storage.
    """
    tenant_id = kwargs["tenant_id"]

    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500

    # --- Try documents table first (PDF / DOCX) ---
    doc_result = supabase.table("documents").select("id, filename, storage_path").eq("id", document_id).eq("tenant_id", tenant_id).execute()
    if doc_result.data:
        doc = doc_result.data[0]
        storage_path = doc.get("storage_path")

        if storage_path:
            try:
                supabase.storage.from_("elorag-docs").remove([storage_path])
            except Exception as e:
                current_app.logger.warning(f"Failed to delete file from storage: {storage_path}, error: {str(e)}")

        delete_result = supabase.table("documents").delete().eq("id", document_id).eq("tenant_id", tenant_id).execute()
        if not delete_result.data:
            return jsonify({"error": "Document not found or already deleted"}), 404

        return jsonify({
            "message": "Document deleted successfully",
            "document_id": document_id,
            "filename": doc.get("filename"),
        }), 200

    # --- Fall back to csv_registry (CSV) ---
    csv_result = supabase.table("csv_registry").select("id, filename, storage_path").eq("id", document_id).eq("tenant_id", tenant_id).execute()
    if not csv_result.data:
        return jsonify({"error": "Document not found"}), 404

    csv_file = csv_result.data[0]
    storage_path = csv_file.get("storage_path")

    if storage_path:
        try:
            supabase.storage.from_("elorag-docs").remove([storage_path])
        except Exception as e:
            current_app.logger.warning(f"Failed to delete file from storage: {storage_path}, error: {str(e)}")

    delete_result = supabase.table("csv_registry").delete().eq("id", document_id).eq("tenant_id", tenant_id).execute()
    if not delete_result.data:
        return jsonify({"error": "CSV file not found or already deleted"}), 404

    return jsonify({
        "message": "CSV file deleted successfully",
        "document_id": document_id,
        "filename": csv_file.get("filename"),
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

    cols = "id, tenant_id, filename, columns, summary, status, uploaded_by, row_count, chunk_count, rejection_reason, created_at, updated_at"
    q = supabase.table("csv_registry").select(cols).eq("tenant_id", tenant_id).order("created_at", desc=True)
    valid_statuses = ("draft", "review", "approved", "rejected", "pending_processing", "processing_failed")
    if status and status in valid_statuses:
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
    Bulk reject CSV files. Marks CSV files as 'rejected' and stores the rejection reason.
    Admin, reviewer, and editor can retrieve rejected CSV files and see the reason.
    
    Request body:
    {
        "file_ids": ["uuid1", "uuid2", ...],  # Required: list of CSV file IDs to reject
        "reason": "Optional rejection reason"  # Optional: reason visible to all staff roles
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
    reason = (body.get("reason") or "").strip()

    if not file_ids:
        return jsonify({"error": "file_ids is required"}), 400
    
    now = datetime.now(timezone.utc).isoformat()

    # Mark CSV files as rejected (keeping record + chunks intact for visibility)
    update_payload = {
        "status": "rejected",
        "rejection_reason": reason or None,
        "updated_at": now,
    }
    result = (
        supabase.table("csv_registry")
        .update(update_payload)
        .eq("tenant_id", tenant_id)
        .in_("id", file_ids)
        .execute()
    )

    rejected_ids = [f["id"] for f in result.data] if result.data else []
    rejected_count = len(rejected_ids)

    response = {
        "message": f"Rejected {rejected_count} CSV file(s)",
        "rejected_count": rejected_count,
        "rejected_file_ids": rejected_ids,
        "action": "bulk_reject",
        "actor": user_id,
        "timestamp": now,
    }
    if reason:
        response["reason"] = reason

    return jsonify(response), 200


@document_upload_bp.route("/csv-registry/<file_id>", methods=["PATCH"])
@require_role("admin", "editor")
def update_csv_file(file_id: str, **kwargs):
    """
    Update CSV file metadata (filename, summary, etc.).
    Only editable fields: filename, summary.
    Status changes should use /csv-registry/<file_id>/status endpoint.
    
    Request body:
    {
        "filename": "new_filename.csv",  # Optional: new filename
        "summary": "Updated summary"     # Optional: new summary
    }
    """
    tenant_id = kwargs["tenant_id"]
    body = request.get_json(silent=True) or {}
    
    supabase = current_app.supabase_client
    if not supabase:
        return jsonify({"error": "Database not configured"}), 500
    
    # Check if CSV file exists
    csv_result = supabase.table("csv_registry").select("id, filename").eq("id", file_id).eq("tenant_id", tenant_id).execute()
    if not csv_result.data:
        return jsonify({"error": "CSV file not found"}), 404
    
    # Build update payload
    update_payload = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    
    # Update filename if provided
    if "filename" in body:
        new_filename = (body.get("filename") or "").strip()
        if not new_filename:
            return jsonify({"error": "filename cannot be empty"}), 400
        update_payload["filename"] = new_filename
    
    # Update summary if provided
    if "summary" in body:
        summary = (body.get("summary") or "").strip()
        update_payload["summary"] = summary if summary else None
    
    if len(update_payload) == 1:  # Only updated_at, nothing to update
        return jsonify({"error": "No fields provided to update"}), 400
    
    # Update CSV file
    result = supabase.table("csv_registry").update(update_payload).eq("id", file_id).eq("tenant_id", tenant_id).execute()
    if not result.data:
        return jsonify({"error": "CSV file not found"}), 404
    
    return jsonify({
        "message": "CSV file updated successfully",
        "file_id": file_id,
        "updated_fields": {k: v for k, v in update_payload.items() if k != "updated_at"}
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

