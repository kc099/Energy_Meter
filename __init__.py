import sys
from importlib import import_module
from pathlib import Path

_pkg_dir = Path(__file__).resolve().parent
if str(_pkg_dir) not in sys.path:
    sys.path.insert(0, str(_pkg_dir))
_inner_pkg_path = _pkg_dir / 'EM_main'
if _inner_pkg_path.exists():
    __path__ = [str(_inner_pkg_path)] + list(__path__)

_inner = import_module('.EM_main', __name__)
celery_app = getattr(_inner, 'celery_app', None)
celery = getattr(_inner, 'celery', celery_app)

__all__ = ('celery_app', 'celery')
