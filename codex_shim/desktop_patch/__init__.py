"""Platform-agnostic ASAR patching helpers for Codex Desktop.

This module contains all ASAR-patching logic extracted from cli.py so that
platform-independent helpers can be reused without pulling in macOS-specific
path resolution, code-signing, or plist handling.
"""

from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path

__all__ = [
    "APP_ASAR_BACKUP_NAME",
    "INFO_PLIST_BACKUP_NAME",
    "MODEL_PICKER_NEEDLE",
    "MODEL_PICKER_REPLACEMENT",
    "MODEL_PICKER_APPLIED",
    "SIDEBAR_RECENT_THREADS_NEEDLE",
    "SIDEBAR_RECENT_THREADS_REPLACEMENT",
    "SIDEBAR_RECENT_THREADS_APPLIED",
    "SIDEBAR_APPLIED_WINDOWS",
    "_app_asar_hash",
    "_app_asar_header_hash",
    "_patch_codex_desktop_bundles",
    "_find_js_bundle",
    "_replace_once",
    "_read_text_lossy",
    "_app_asar_is_patched",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_ASAR_BACKUP_NAME = "app.asar.before-codex-shim-model-picker-patch"
INFO_PLIST_BACKUP_NAME = "Info.plist.before-codex-shim-model-picker-patch"

MODEL_PICKER_NEEDLE = re.compile(
    r"(?P<lhs>(?:let )?\w+=)"
    r"(?:\w+\.useHiddenModels|\w+)"
    r"&&\w+!==`amazonBedrock`"
    r"(?P<sep>[,;])"
)
MODEL_PICKER_REPLACEMENT = r"\g<lhs>!1\g<sep>"
MODEL_PICKER_APPLIED = re.compile(
    r"(?:let )?\w+=!1[,;][^\n]{0,300}\.forEach"
)

SIDEBAR_RECENT_THREADS_NEEDLE = re.compile(
    r"listRecentThreads\(\{cursor:e,limit:t(?:,useStateDbOnly:\w+(?:=!\d)?)?\}\)\{return this\.params\.requestClient\.sendRequest\(`thread/list`,"
    r"\{limit:t,cursor:e,sortKey:this\.recentConversationSortKey,modelProviders:null,archived:!1,sourceKinds:(\w+)(?:,useStateDbOnly:\w+)?\}\)\}"
)
SIDEBAR_RECENT_THREADS_REPLACEMENT = (
    r"listRecentThreads({cursor:e,limit:t}){return this.params.requestClient.sendRequest(`thread/list`,"
    r"{limit:t,cursor:e,sortKey:this.recentConversationSortKey,modelProviders:[],archived:!1,sourceKinds:\1})}"
)
SIDEBAR_RECENT_THREADS_APPLIED = re.compile(
    r"\.recentConversationSortKey,modelProviders:\[\],archived:!1,sourceKinds:\w+"
)

# Windows sidebar uses listAllThreads (not listRecentThreads like macOS).
# After patching, modelProviders:null becomes modelProviders:[] or modelProviders: [].
SIDEBAR_APPLIED_WINDOWS = re.compile(
    r"listAllThreads\(\{[^}]*modelProviders:\s*\["
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _app_asar_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _app_asar_header_hash(path: Path) -> str:
    with path.open("rb") as f:
        _, _, _, json_size = struct.unpack("<4I", f.read(16))
        header_json = f.read(json_size)
    return hashlib.sha256(header_json).hexdigest()


def _patch_codex_desktop_bundles(workdir: Path) -> bool | None:
    patches = [
        (
            "model picker allowlist filter",
            [
                "models-and-reasoning-efforts-*.js",
                "model-queries-*.js",
                "*.js",
            ],
            MODEL_PICKER_NEEDLE,
            MODEL_PICKER_REPLACEMENT,
            MODEL_PICKER_APPLIED,
        ),
        (
            "shim-mode sidebar provider filter",
            ["app-server-manager-signals-*.js", "*.js"],
            SIDEBAR_RECENT_THREADS_NEEDLE,
            SIDEBAR_RECENT_THREADS_REPLACEMENT,
            SIDEBAR_RECENT_THREADS_APPLIED,
        ),
    ]
    changed = False
    for label, globs, needle, replacement, applied in patches:
        bundle_file = _find_js_bundle(workdir, globs, needle, applied)
        if bundle_file is None:
            print(f"Could not find the expected {label} in Codex Desktop.", file=sys.stderr)
            return None
        result = _replace_once(bundle_file, needle, replacement, applied)
        if result is None:
            print(f"Could not patch the expected {label} in Codex Desktop.", file=sys.stderr)
            return None
        if result:
            changed = True
            print(f"Patched Codex Desktop {label}.")
        else:
            print(f"Codex Desktop {label} patch is already applied.")
    return changed


def _find_js_bundle(
    workdir: Path,
    globs: list[str],
    needle: re.Pattern[str],
    applied: re.Pattern[str],
) -> Path | None:
    assets_dir = workdir / "webview" / "assets"
    if not assets_dir.exists():
        return None
    candidates: list[Path] = []
    for pattern in globs:
        candidates.extend(p for p in sorted(assets_dir.glob(pattern)) if p not in candidates)
    for path in candidates:
        text = _read_text_lossy(path)
        if needle.search(text) or applied.search(text):
            return path
    return None


def _replace_once(
    path: Path,
    needle: re.Pattern[str],
    replacement: str,
    applied: re.Pattern[str],
) -> bool | None:
    text = _read_text_lossy(path)
    matches = needle.findall(text)
    if not matches:
        if applied.search(text):
            return False
        return None
    if len(matches) != 1:
        return None
    path.write_text(needle.sub(replacement, text, count=1))
    return True


def _read_text_lossy(path: Path) -> str:
    try:
        return path.read_text()
    except UnicodeDecodeError:
        return path.read_text(errors="ignore")


def _app_asar_is_patched(app_asar: Path) -> bool:
    try:
        text = app_asar.read_bytes().decode("utf-8", errors="ignore")
    except OSError:
        return False
    if MODEL_PICKER_APPLIED.search(text) is None:
        return False
    return (SIDEBAR_RECENT_THREADS_APPLIED.search(text) is not None
            or SIDEBAR_APPLIED_WINDOWS.search(text) is not None)
