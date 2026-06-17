from pathlib import Path

from django.conf import settings
from django.http import FileResponse, Http404


FRONTEND_DIST_DIR = settings.BASE_DIR / "frontend" / "dist"


def _frontend_file(path: str) -> Path:
    file_path = (FRONTEND_DIST_DIR / path).resolve()
    if FRONTEND_DIST_DIR.resolve() not in file_path.parents and file_path != FRONTEND_DIST_DIR.resolve():
        raise Http404("Invalid frontend path")
    if not file_path.exists() or not file_path.is_file():
        raise Http404("Frontend asset not found")
    return file_path


def frontend_asset(request, asset_path: str):
    return FileResponse(_frontend_file(f"assets/{asset_path}").open("rb"))


def frontend_app(request, path: str = ""):
    candidate = None
    if path:
        candidate_path = (FRONTEND_DIST_DIR / path).resolve()
        if FRONTEND_DIST_DIR.resolve() in candidate_path.parents and candidate_path.exists() and candidate_path.is_file():
            candidate = candidate_path

    target = candidate or _frontend_file("index.html")
    return FileResponse(target.open("rb"))
