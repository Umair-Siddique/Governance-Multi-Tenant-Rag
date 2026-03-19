"""
Celery tasks for document processing and embedding.
Handles PDF/DOCX/image extraction (images via Tesseract OCR), CSV processing, and Pinecone publishing in background.
"""
import io
import uuid
from datetime import datetime, timezone
from pathlib import Path

from celery import Celery, Task
from supabase import create_client
from openai import OpenAI

from config import Config
from utils.document_utils import (
    extract_and_preprocess,
    recursive_chunk,
    parse_csv,
    csv_rows_to_chunks,
    generate_csv_summary_with_llm,
    DEFAULT_CHUNK_SIZE,
    DEFAULT_CHUNK_OVERLAP,
)
from utils.pinecone_service import PineconeService


def make_celery(app):
    """Create Celery instance with Flask app context."""
    celery = Celery(
        app.import_name,
        broker=app.config['CELERY_BROKER_URL'],
        backend=app.config['CELERY_RESULT_BACKEND'],
    )
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
    )
    
    class ContextTask(celery.Task):
        """Make celery tasks work with Flask app context."""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery


# Celery instance will be initialized by app factory
celery = None


def _process_pending_documents_impl(self):
    """
    Periodic task to process pending documents from storage.
    Fetches documents with status 'pending_processing' and processes them one by one.
    """
    supabase = _get_supabase_client()
    
    # Process pending PDF/DOCX documents
    pending_docs = (
        supabase.table("documents")
        .select("id, tenant_id, storage_path, filename, file_type")
        .eq("status", "pending_processing")
        .order("created_at")
        .limit(10)  # Process 10 at a time to avoid overload
        .execute()
    )
    
    processed = 0
    for doc in (pending_docs.data or []):
        try:
            _process_document_from_storage_impl(
                self,
                tenant_id=doc["tenant_id"],
                document_id=doc["id"],
                storage_path=doc["storage_path"],
                filename=doc["filename"],
                file_type=doc["file_type"],
            )
            processed += 1
        except Exception as e:
            print(f"Failed to process document {doc['id']}: {str(e)}")
            continue
    
    # Process pending CSV files
    pending_csv = (
        supabase.table("csv_registry")
        .select("id, tenant_id, storage_path, filename")
        .eq("status", "pending_processing")
        .order("created_at")
        .limit(10)
        .execute()
    )
    
    for csv_file in (pending_csv.data or []):
        try:
            _process_document_from_storage_impl(
                self,
                tenant_id=csv_file["tenant_id"],
                document_id=csv_file["id"],
                storage_path=csv_file["storage_path"],
                filename=csv_file["filename"],
                file_type="csv",
            )
            processed += 1
        except Exception as e:
            print(f"Failed to process CSV {csv_file['id']}: {str(e)}")
            continue
    
    return {"processed": processed}


def init_celery_from_app(app):
    """Initialize Celery from Flask app (called after app creation)."""
    global celery, process_document_upload, process_csv_upload, publish_to_pinecone_task, process_document_from_storage, process_pending_documents, process_document_batch
    celery = make_celery(app)
    
    # Register tasks after celery is initialized
    process_document_upload = celery.task(bind=True)(_process_document_upload_impl)
    process_csv_upload = celery.task(bind=True)(_process_csv_upload_impl)
    publish_to_pinecone_task = celery.task(bind=True)(_publish_to_pinecone_impl)
    process_document_from_storage = celery.task(bind=True)(_process_document_from_storage_impl)
    process_document_batch = celery.task(bind=True)(_process_document_batch_impl)
    
    # Periodic task to process pending documents (runs every 30 seconds)
    process_pending_documents = celery.task(bind=True, name='tasks.document_tasks.process_pending_documents')(_process_pending_documents_impl)
    celery.conf.beat_schedule = {
        'process-pending-documents': {
            'task': 'tasks.document_tasks.process_pending_documents',
            'schedule': 30.0,  # Run every 30 seconds
        },
    }
    
    return celery


def _get_supabase_client():
    """Get Supabase client."""
    return create_client(Config.SUPABASE_URL, Config.SUPABASE_SECRET_KEY)


def _get_openai_client():
    """Get OpenAI client."""
    return OpenAI(api_key=Config.OPENAI_API_KEY)


def _get_pinecone_service():
    """Get Pinecone service."""
    return PineconeService()


def _embed_batch(openai_client, texts: list, batch_size: int = 100):
    """Embed texts with text-embedding-3-small (1536 dims). Returns list of embedding lists."""
    out = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i : i + batch_size]
        resp = openai_client.embeddings.create(
            model="text-embedding-3-small",
            input=batch,
            dimensions=1536,
        )
        out.extend([e.embedding for e in resp.data])
    return out


def _update_task_progress(task_self, **meta):
    """Best-effort task progress update for live status polling."""
    if not hasattr(task_self, "update_state"):
        return
    try:
        task_self.update_state(state="PROGRESS", meta=meta)
    except Exception:
        # Progress reporting should never break business flow
        pass


def _process_document_upload_impl(self, tenant_id: str, user_id: str, filename: str, file_data: bytes, file_ext: str):
    """
    Process document upload (PDF/DOCX): extract, preprocess, chunk, and store in Supabase.
    
    Args:
        tenant_id: Tenant ID
        user_id: User ID who uploaded
        filename: Original filename
        file_data: File content as bytes
        file_ext: File extension (.pdf or .docx)
    
    Returns:
        dict with document_id, filename, status, chunk_count
    """
    try:
        supabase = _get_supabase_client()
        tesseract_cmd = Config.TESSERACT_CMD
        
        # Extract and preprocess text
        text = extract_and_preprocess(
            io.BytesIO(file_data),
            file_ext=file_ext,
            tesseract_cmd=tesseract_cmd,
        )
        
        if not text or not text.strip():
            raise ValueError("Could not extract any text from the document")
        
        # Chunk the text
        chunks = recursive_chunk(
            text,
            chunk_size=DEFAULT_CHUNK_SIZE,
            chunk_overlap=DEFAULT_CHUNK_OVERLAP,
        )
        
        if not chunks:
            raise ValueError("No chunks produced after processing")
        
        # Store in Supabase
        now = datetime.now(timezone.utc).isoformat()
        doc_id = str(uuid.uuid4())
        
        doc_row = {
            "id": doc_id,
            "tenant_id": tenant_id,
            "filename": filename,
            "file_type": file_ext.lstrip("."),
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
        
        return {
            "document_id": doc_id,
            "filename": filename,
            "status": "draft",
            "chunk_count": len(chunks),
            "chunk_size": DEFAULT_CHUNK_SIZE,
            "chunk_overlap": DEFAULT_CHUNK_OVERLAP,
        }
    except Exception as e:
        if hasattr(self, 'update_state'):
            self.update_state(state='FAILURE', meta={'error': str(e)})
        raise


def _process_csv_upload_impl(self, tenant_id: str, user_id: str, filename: str, file_data: bytes):
    """
    Process CSV upload: parse, create registry entry, generate chunks.
    
    Args:
        tenant_id: Tenant ID
        user_id: User ID who uploaded
        filename: Original filename
        file_data: File content as bytes
    
    Returns:
        dict with file_id, filename, status, columns, row_count, chunk_count
    """
    try:
        supabase = _get_supabase_client()
        openai_client = _get_openai_client()
        
        # Parse CSV
        columns, rows = parse_csv(io.BytesIO(file_data))
        if not columns:
            raise ValueError("CSV has no header or could not be parsed")
        if not rows:
            raise ValueError("CSV has no data rows")
        
        # Generate chunks
        chunks = csv_rows_to_chunks(columns, rows, chunk_size=DEFAULT_CHUNK_SIZE)
        if not chunks:
            raise ValueError("No chunks produced from CSV")
        
        # Generate summary with LLM
        summary = ""
        try:
            summary = generate_csv_summary_with_llm(columns, rows, openai_client)
        except Exception:
            pass  # Summary is optional
        
        # Store in Supabase
        now = datetime.now(timezone.utc).isoformat()
        file_id = str(uuid.uuid4())
        
        registry_row = {
            "id": file_id,
            "tenant_id": tenant_id,
            "filename": filename,
            "columns": columns,
            "summary": summary or None,
            "status": "draft",
            "uploaded_by": user_id,
            "row_count": len(rows),
            "chunk_count": len(chunks),
            "created_at": now,
            "updated_at": now,
        }
        supabase.table("csv_registry").insert(registry_row).execute()
        
        chunk_rows = [
            {
                "csv_file_id": file_id,
                "tenant_id": tenant_id,
                "chunk_index": i,
                "content": c,
                "char_count": len(c),
            }
            for i, c in enumerate(chunks)
        ]
        supabase.table("csv_chunks").insert(chunk_rows).execute()
        
        return {
            "file_id": file_id,
            "filename": filename,
            "status": "draft",
            "columns": columns,
            "row_count": len(rows),
            "chunk_count": len(chunks),
            "summary": summary[:500] if summary else None,
        }
    except Exception as e:
        if hasattr(self, 'update_state'):
            self.update_state(state='FAILURE', meta={'error': str(e)})
        raise


def _publish_to_pinecone_impl(self, tenant_id: str, document_ids: list = None, file_ids: list = None):
    """
    Publish approved documents and CSV files to Pinecone.
    
    Args:
        tenant_id: Tenant ID
        document_ids: Optional list of document IDs to publish (if None, publishes all approved)
        file_ids: Optional list of CSV file IDs to publish (if None, publishes all approved)
    
    Returns:
        dict with counts of published documents, CSV files, and chunks
    """
    try:
        supabase = _get_supabase_client()
        pinecone_service = _get_pinecone_service()
        openai_client = _get_openai_client()
        _update_task_progress(
            self,
            task_type="publish_to_pinecone",
            stage="starting",
            message="Starting publish pipeline",
            documents_matched=0,
            csv_files_matched=0,
            chunks_prepared=0,
        )
        
        all_vectors = []
        docs_published = 0
        csv_files_published = 0
        
        # Process documents (PDF/DOCX)
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
        _update_task_progress(
            self,
            task_type="publish_to_pinecone",
            stage="documents_selected",
            message="Selected approved documents",
            documents_matched=len(docs),
            csv_files_matched=0,
            chunks_prepared=len(all_vectors),
        )
        if docs:
            doc_ids = [d["id"] for d in docs]
            doc_filenames = {d["id"]: d["filename"] for d in docs}
            chunks_result = (
                supabase.table("document_chunks")
                .select("id, document_id, chunk_index, content")
                .eq("tenant_id", tenant_id)
                .in_("document_id", doc_ids)
                .order("document_id")
                .order("chunk_index")
                .execute()
            )
            doc_chunks = chunks_result.data or []
            if doc_chunks:
                _update_task_progress(
                    self,
                    task_type="publish_to_pinecone",
                    stage="embedding_documents",
                    message="Embedding document chunks",
                    documents_matched=len(docs),
                    csv_files_matched=0,
                    chunks_prepared=len(all_vectors),
                    document_chunks=len(doc_chunks),
                )
                texts = [c["content"] for c in doc_chunks]
                embeddings = _embed_batch(openai_client, texts)
                for chunk, embedding in zip(doc_chunks, embeddings):
                    chunk_id = chunk["id"]
                    document_id = chunk["document_id"]
                    filename = doc_filenames.get(document_id, "")
                    all_vectors.append({
                        "id": str(chunk_id),
                        "values": embedding,
                        "metadata": {
                            "tenant_id": str(tenant_id),
                            "document_id": str(document_id),
                            "source_type": "document",
                            "chunk_id": str(chunk_id),
                            "chunk_index": int(chunk["chunk_index"]),
                            "filename": str(filename),
                            "content": str(chunk["content"])[:10000],
                        },
                    })
                docs_published = len(docs)
                _update_task_progress(
                    self,
                    task_type="publish_to_pinecone",
                    stage="documents_embedded",
                    message="Document chunks embedded",
                    documents_matched=len(docs),
                    csv_files_matched=0,
                    chunks_prepared=len(all_vectors),
                    document_chunks=len(doc_chunks),
                )
        
        # Process CSV files
        if file_ids:
            reg_result = (
                supabase.table("csv_registry")
                .select("id, filename")
                .eq("tenant_id", tenant_id)
                .eq("status", "approved")
                .in_("id", file_ids)
                .execute()
            )
        else:
            reg_result = (
                supabase.table("csv_registry")
                .select("id, filename")
                .eq("tenant_id", tenant_id)
                .eq("status", "approved")
                .execute()
            )
        
        csv_files = reg_result.data or []
        _update_task_progress(
            self,
            task_type="publish_to_pinecone",
            stage="csv_selected",
            message="Selected approved CSV files",
            documents_matched=len(docs),
            csv_files_matched=len(csv_files),
            chunks_prepared=len(all_vectors),
        )
        if csv_files:
            csv_id_list = [f["id"] for f in csv_files]
            filenames = {f["id"]: f["filename"] for f in csv_files}
            chunks_result = (
                supabase.table("csv_chunks")
                .select("id, csv_file_id, chunk_index, content")
                .eq("tenant_id", tenant_id)
                .in_("csv_file_id", csv_id_list)
                .order("csv_file_id")
                .order("chunk_index")
                .execute()
            )
            csv_chunks = chunks_result.data or []
            if csv_chunks:
                _update_task_progress(
                    self,
                    task_type="publish_to_pinecone",
                    stage="embedding_csv",
                    message="Embedding CSV chunks",
                    documents_matched=len(docs),
                    csv_files_matched=len(csv_files),
                    chunks_prepared=len(all_vectors),
                    csv_chunks=len(csv_chunks),
                )
                texts = [c["content"] for c in csv_chunks]
                embeddings = _embed_batch(openai_client, texts)
                for chunk, embedding in zip(csv_chunks, embeddings):
                    csv_file_id = chunk["csv_file_id"]
                    filename = filenames.get(csv_file_id, "")
                    chunk_id = chunk["id"]
                    all_vectors.append({
                        "id": f"csv_{chunk_id}",
                        "values": embedding,
                        "metadata": {
                            "tenant_id": str(tenant_id),
                            "file_id": str(csv_file_id),
                            "source_type": "csv",
                            "chunk_id": str(chunk_id),
                            "chunk_index": int(chunk["chunk_index"]),
                            "filename": str(filename),
                            "content": str(chunk["content"])[:10000],
                        },
                    })
                csv_files_published = len(csv_files)
                _update_task_progress(
                    self,
                    task_type="publish_to_pinecone",
                    stage="csv_embedded",
                    message="CSV chunks embedded",
                    documents_matched=len(docs),
                    csv_files_matched=len(csv_files),
                    chunks_prepared=len(all_vectors),
                    csv_chunks=len(csv_chunks),
                )
        
        if not all_vectors:
            return {
                "message": "No approved documents or CSV files to publish",
                "documents_published": 0,
                "csv_files_published": 0,
                "chunks_upserted": 0,
            }
        
        # Upsert to Pinecone
        _update_task_progress(
            self,
            task_type="publish_to_pinecone",
            stage="upserting_vectors",
            message="Upserting vectors to Pinecone",
            documents_matched=len(docs),
            csv_files_matched=len(csv_files),
            chunks_prepared=len(all_vectors),
        )
        pinecone_service.upsert_vectors(tenant_id, all_vectors)
        
        return {
            "message": "Content published to vector store",
            "documents_published": docs_published,
            "csv_files_published": csv_files_published,
            "chunks_upserted": len(all_vectors),
        }
    except Exception as e:
        if hasattr(self, 'update_state'):
            self.update_state(state='FAILURE', meta={'error': str(e)})
        raise


def _process_document_from_storage_impl(self, tenant_id: str, document_id: str, storage_path: str, filename: str, file_type: str):
    """
    Process document from Supabase Storage: fetch, extract, preprocess, chunk, and store in Supabase.
    Deletes the file from storage after successful processing.
    
    Args:
        tenant_id: Tenant ID
        document_id: Document ID in database
        storage_path: Path to file in Supabase Storage
        filename: Original filename
        file_type: File type (pdf, docx, csv, or image e.g. jpg, png)
    
    Returns:
        dict with document_id, filename, status, chunk_count
    """
    supabase = _get_supabase_client()
    storage_bucket = "elorag-docs"
    
    try:
        # Fetch file from Supabase Storage
        file_data = supabase.storage.from_(storage_bucket).download(storage_path)
        if not file_data:
            raise ValueError(f"Failed to download file from storage: {storage_path}")
        
        # Process based on file type
        if file_type == "csv":
            return _process_csv_from_storage(supabase, tenant_id, document_id, storage_path, filename, file_data, self)
        else:
            return _process_document_from_storage_data(supabase, tenant_id, document_id, storage_path, filename, file_type, file_data, self)
            
    except Exception as e:
        # Update status to failed
        try:
            if file_type == "csv":
                supabase.table("csv_registry").update({
                    "status": "processing_failed",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }).eq("id", document_id).eq("tenant_id", tenant_id).execute()
            else:
                supabase.table("documents").update({
                    "status": "processing_failed",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }).eq("id", document_id).eq("tenant_id", tenant_id).execute()
        except Exception:
            pass  # Ignore update errors
        
        if hasattr(self, 'update_state'):
            self.update_state(state='FAILURE', meta={'error': str(e)})
        raise


def _process_document_from_storage_data(supabase, tenant_id: str, document_id: str, storage_path: str, filename: str, file_ext: str, file_data: bytes, task_self):
    """Process PDF/DOCX document from storage data."""
    tesseract_cmd = Config.TESSERACT_CMD
    
    # Extract and preprocess text
    text = extract_and_preprocess(
        io.BytesIO(file_data),
        file_ext=f".{file_ext}",
        tesseract_cmd=tesseract_cmd,
    )
    
    if not text or not text.strip():
        raise ValueError("Could not extract any text from the document")
    
    # Chunk the text
    chunks = recursive_chunk(
        text,
        chunk_size=DEFAULT_CHUNK_SIZE,
        chunk_overlap=DEFAULT_CHUNK_OVERLAP,
    )
    
    if not chunks:
        raise ValueError("No chunks produced after processing")
    
    # Update document record
    now = datetime.now(timezone.utc).isoformat()
    supabase.table("documents").update({
        "status": "draft",
        "raw_text": text[:100_000] if len(text) > 100_000 else text,
        "chunk_count": len(chunks),
        "updated_at": now,
    }).eq("id", document_id).eq("tenant_id", tenant_id).execute()
    
    # Insert chunks
    chunk_rows = [
        {
            "document_id": document_id,
            "tenant_id": tenant_id,
            "chunk_index": i,
            "content": c,
            "char_count": len(c),
        }
        for i, c in enumerate(chunks)
    ]
    supabase.table("document_chunks").insert(chunk_rows).execute()
    
    # Delete file from storage after successful processing
    try:
        supabase.storage.from_("elorag-docs").remove([storage_path])
    except Exception as e:
        # Log but don't fail - file processing succeeded
        print(f"Warning: Failed to delete file from storage: {storage_path}, error: {str(e)}")
    
    return {
        "document_id": document_id,
        "filename": filename,
        "status": "draft",
        "chunk_count": len(chunks),
        "chunk_size": DEFAULT_CHUNK_SIZE,
        "chunk_overlap": DEFAULT_CHUNK_OVERLAP,
    }


def _process_csv_from_storage(supabase, tenant_id: str, file_id: str, storage_path: str, filename: str, file_data: bytes, task_self):
    """Process CSV file from storage data."""
    openai_client = _get_openai_client()
    
    # Parse CSV
    columns, rows = parse_csv(io.BytesIO(file_data))
    if not columns:
        raise ValueError("CSV has no header or could not be parsed")
    if not rows:
        raise ValueError("CSV has no data rows")
    
    # Generate chunks
    chunks = csv_rows_to_chunks(columns, rows, chunk_size=DEFAULT_CHUNK_SIZE)
    if not chunks:
        raise ValueError("No chunks produced from CSV")
    
    # Generate summary with LLM
    summary = ""
    try:
        summary = generate_csv_summary_with_llm(columns, rows, openai_client)
    except Exception:
        pass  # Summary is optional
    
    # Update registry record
    now = datetime.now(timezone.utc).isoformat()
    supabase.table("csv_registry").update({
        "status": "draft",
        "columns": columns,
        "summary": summary or None,
        "row_count": len(rows),
        "chunk_count": len(chunks),
        "updated_at": now,
    }).eq("id", file_id).eq("tenant_id", tenant_id).execute()
    
    # Insert chunks
    chunk_rows = [
        {
            "csv_file_id": file_id,
            "tenant_id": tenant_id,
            "chunk_index": i,
            "content": c,
            "char_count": len(c),
        }
        for i, c in enumerate(chunks)
    ]
    supabase.table("csv_chunks").insert(chunk_rows).execute()
    
    # Delete file from storage after successful processing
    try:
        supabase.storage.from_("elorag-docs").remove([storage_path])
    except Exception as e:
        # Log but don't fail - file processing succeeded
        print(f"Warning: Failed to delete file from storage: {storage_path}, error: {str(e)}")
    
    return {
        "file_id": file_id,
        "filename": filename,
        "status": "draft",
        "columns": columns,
        "row_count": len(rows),
        "chunk_count": len(chunks),
        "summary": summary[:500] if summary else None,
    }


def _process_document_batch_impl(self, tenant_id: str, batch_items: list):
    """
    Process a batch of documents (PDF/DOCX/CSV/images) from storage as a single background task.
    Provides one task_id for the entire upload batch instead of one per document.

    Args:
        tenant_id: Tenant ID
        batch_items: List of dicts, each with keys:
            - document_id (str)
            - storage_path (str)
            - filename (str)
            - file_type (str)  e.g. "pdf", "docx", "csv", "jpg", "png"

    Returns:
        dict with total, processed, failed counts and per-item results/errors.
    """
    results = []
    errors = []
    total = len(batch_items)

    _update_task_progress(
        self,
        task_type="document_batch",
        stage="starting",
        message="Batch processing started",
        total=total,
        processed=0,
        failed=0,
    )

    for item in batch_items:
        _update_task_progress(
            self,
            task_type="document_batch",
            stage="processing_item",
            message=f"Processing {item.get('filename', 'document')}",
            total=total,
            processed=len(results),
            failed=len(errors),
            current_document_id=item.get("document_id"),
            current_filename=item.get("filename"),
            current_file_type=item.get("file_type"),
        )
        try:
            result = _process_document_from_storage_impl(
                self,
                tenant_id=tenant_id,
                document_id=item["document_id"],
                storage_path=item["storage_path"],
                filename=item["filename"],
                file_type=item["file_type"],
            )
            results.append(result)
        except Exception as e:
            errors.append({
                "document_id": item["document_id"],
                "filename": item["filename"],
                "error": str(e),
            })
        _update_task_progress(
            self,
            task_type="document_batch",
            stage="processing_item",
            message="Batch processing in progress",
            total=total,
            processed=len(results),
            failed=len(errors),
            progress_percent=int(((len(results) + len(errors)) / total) * 100) if total else 100,
        )

    return {
        "total": total,
        "processed": len(results),
        "failed": len(errors),
        "results": results,
        "errors": errors,
    }


# Tasks will be registered after celery is initialized
process_document_upload = None
process_csv_upload = None
publish_to_pinecone_task = None
process_document_from_storage = None
process_pending_documents = None
process_document_batch = None



