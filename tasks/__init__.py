"""
Celery tasks module.
Tasks are initialized lazily after Celery is set up.
Import directly from tasks.document_tasks when needed.
"""
# Tasks are initialized in init_celery_from_app()
# Import them directly from tasks.document_tasks when needed

__all__ = [
    "process_document_upload",
    "process_csv_upload",
    "publish_to_pinecone_task",
]

