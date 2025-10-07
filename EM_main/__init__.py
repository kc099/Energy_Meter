try:
    from .celery import app as celery_app  # noqa: F401
    celery = celery_app
except ModuleNotFoundError:  # pragma: no cover - optional dependency during local dev/testing
    celery_app = None
    celery = None

__all__ = ("celery_app", "celery")
import pymysql
pymysql.install_as_MySQLdb()
