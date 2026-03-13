"""
Celery worker entry point.

On Windows, use: celery -A celery_worker.celery worker --pool=solo --loglevel=info
On Linux/Mac, use: celery -A celery_worker.celery worker --loglevel=info

The --pool=solo flag is required on Windows because prefork (default) doesn't work on Windows.
"""
import sys
from app import create_app
from tasks.document_tasks import init_celery_from_app

app = create_app()
celery = init_celery_from_app(app)

# Export celery for celery command line
__all__ = ['celery']

# Auto-detect Windows and suggest solo pool
if sys.platform == 'win32':
    print("\n⚠️  Windows detected: Use --pool=solo when starting the worker:")
    print("   celery -A celery_worker.celery worker --pool=solo --loglevel=info\n")

