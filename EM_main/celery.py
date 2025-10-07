"""Celery application instance for asynchronous tasks."""
import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "EM_main.settings")

app = Celery("EM_main")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    """Simple debug hook to verify Celery is wired up."""
    print(f"Request: {self.request!r}")
