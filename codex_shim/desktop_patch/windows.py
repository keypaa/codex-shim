"""Windows-specific Codex detection and process lifecycle helpers.

Used for finding Codex installs (MSIX, portable, direct install),
detecting MSIX read-only paths, validating install integrity, and
managing the Codex process before/after ASAR patching.
"""

from __future__ import annotations

import logging
import re
import struct
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

MSIX_PREFIX = Path("C:/Program Files/WindowsApps")

# ---------------------------------------------------------------------------
# Windows-specific needle patterns (Phase 0 confirmed)
# macOS: let u=c.useHiddenModels&&o!==`amazonBedrock`,d;
# Windows: s = i && e !== `amazonBedrock`  (model-list-filter-BOpqDcyc.js)
# ---------------------------------------------------------------------------

MODEL_PICKER_NEEDLE_WINDOWS = re.compile(
    r'(\w+)\s*=\s*(\w+)\s*&&\s*\w+\s*!==\s*`amazonBedrock`'
)
MODEL_PICKER_REPLACEMENT_WINDOWS = r'\1=!1'
MODEL_PICKER_APPLIED_WINDOWS = "codex-shim.patch.applied"

# Windows sidebar uses listAllThreads (not listRecentThreads like macOS)
# Simple string replacement: modelProviders:null -> modelProviders:[]
SIDEBAR_NEEDLE_WINDOWS = "modelProviders:null"
SIDEBAR_REPLACEMENT_WINDOWS = "modelProviders:[]"


def _sys_platform() -> str:
    """Return ``sys.platform``.

    Exists as a separate function so tests can monkeypatch it without
    touching the real ``sys.platform``.
    """
    return sys.platform


# ---------------------------------------------------------------------------
# Install detection
# ---------------------------------------------------------------------------


def find_codex_install(target: str | None = None) -> Path | None:
    """Locate a Codex Desktop install directory.

    If *target* is provided it is validated as a Codex install and
    returned immediately.  Otherwise auto-detection probes these
    locations in order:

    1. MSIX install via ``Get-AppxPackage -Name "OpenAI.Codex"``
    2. ``%LOCALAPPDATA%\\Codex\\versions\\*\\*`` (vaportail / portable)
    3. ``*\\CodexPortable\\versions\\*\\*`` (manual portable)
    4. ``%LOCALAPPDATA%\\Programs\\Codex\\`` (direct installer)
    5. ``Codex.exe`` on ``PATH``

    Parameters
    ----------
    target:
        An explicit path to a Codex install directory (optional).

    Returns
    -------
    The :class:`Path` to a valid Codex install directory, or ``None``
    if no install was found.
    """
    if target is not None:
        p = Path(target)
        return p if validate_codex_install(p) else None

    # 1a. MSIX — query PackageManager via PowerShell
    msix = _find_msix_install()
    if msix is not None:
        return msix

    # 1b. MSIX fallback — scan WindowsApps directories directly
    msix_fb = _find_msix_install_fallback()
    if msix_fb is not None:
        return msix_fb

    # 2. Vaportail / portable: %LOCALAPPDATA%\Codex\versions\*\*
    local_appdata = _get_local_appdata()
    if local_appdata is not None:
        candidate = _find_in_versions_dir(local_appdata / "Codex")
        if candidate is not None:
            return candidate

    # 3. Manual portable: *\CodexPortable\versions\*\*
    candidate = _find_in_portable_wildcard()
    if candidate is not None:
        return candidate

    # 4. Direct installer: %LOCALAPPDATA%\Programs\Codex\
    if local_appdata is not None:
        direct = local_appdata / "Programs" / "Codex"
        if validate_codex_install(direct):
            return direct

    # 5. PATH lookup
    candidate = _find_on_path()
    if candidate is not None:
        return candidate

    return None


def is_msix_readonly(install_path: Path) -> bool:
    """Check if *install_path* lives under the MSIX package root.

    Returns ``True`` only when the path starts with
    ``C:\\Program Files\\WindowsApps\\``.  Admin/elevation is never
    probed — this is a purely path-prefix check.

    Parameters
    ----------
    install_path:
        The install directory to check.

    Returns
    -------
    ``True`` if the path matches the MSIX WindowsApps prefix.
    """
    try:
        resolved = install_path.resolve()
    except (OSError, RuntimeError):
        resolved = install_path
    return MSIX_PREFIX in resolved.parents or str(resolved).startswith(
        str(MSIX_PREFIX)
    )


def validate_codex_install(path: Path) -> bool:
    """Verify that *path* looks like a real Codex Desktop install.

    Checks:

    - At least one of ``Codex.exe`` or ``app\\Codex.exe`` exists.
    - At least one of ``resources\\app.asar`` or ``app\\app.asar`` exists.
    - The ASAR archive contains a ``webview/assets/`` entry.

    Parameters
    ----------
    path:
        Directory to validate.

    Returns
    -------
    ``True`` if all checks pass.
    """
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError):
        resolved = path

    # --- Check for Codex.exe ---
    exe_found = (resolved / "Codex.exe").is_file() or (
        resolved / "app" / "Codex.exe"
    ).is_file()
    if not exe_found:
        return False

    # --- Check for app.asar ---
    asar_path: Path | None = None
    for candidate in [resolved / "resources" / "app.asar", resolved / "app" / "app.asar"]:
        if candidate.is_file():
            asar_path = candidate
            break
    if asar_path is None:
        return False

    # --- Check ASAR contains webview/assets/ ---
    return _asar_has_webview(asar_path)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_MSIX_PACKAGE_NAME = "OpenAI.Codex"
"""Package name passed to ``Get-AppxPackage`` when probing for MSIX installs."""


def _get_local_appdata() -> Path | None:
    """Return ``%LOCALAPPDATA%`` as a :class:`Path`, or ``None``."""
    import os as _os

    raw = _os.environ.get("LOCALAPPDATA")
    if raw is None:
        return None
    try:
        return Path(raw)
    except (TypeError, RuntimeError):
        return None


def _find_msix_install() -> Path | None:
    """Query PowerShell ``Get-AppxPackage`` to locate the MSIX Codex install.

    Returns the resolved package install path, or ``None`` if the
    package is not installed or the query fails.
    """
    script = (
        f'$pkg = Get-AppxPackage -Name "{_MSIX_PACKAGE_NAME}" 2>$null; '
        f"if ($pkg) {{ $pkg.InstallLocation }} else {{ '' }}"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None

    output = result.stdout.strip()
    if not output or result.returncode != 0:
        return None

    p = Path(output)
    return p if p.is_dir() else None


def _find_msix_install_fallback() -> Path | None:
    """Scan ``C:\\Program Files\\WindowsApps\\`` for Codex MSIX directories.

    Used when ``Get-AppxPackage`` fails (e.g. no PowerShell, or the
    command is blocked by policy).  Matches directories named like
    ``OpenAI.Codex_*``.
    """
    windows_apps = Path("C:/Program Files/WindowsApps")
    if not windows_apps.is_dir():
        return None

    try:
        for entry in windows_apps.iterdir():
            if entry.is_dir() and entry.name.startswith("OpenAI.Codex"):
                # MSIX layout: Codex.exe is under app/ subdirectory
                if (entry / "app" / "Codex.exe").is_file():
                    return entry
        return None
    except PermissionError:
        return None


def _find_in_versions_dir(base: Path) -> Path | None:
    """Search ``<base>/versions/<ver>/`` for a valid Codex install."""
    versions = base / "versions"
    if not versions.is_dir():
        return None
    try:
        for ver_dir in sorted(versions.iterdir(), reverse=True):
            if not ver_dir.is_dir():
                continue
            if validate_codex_install(ver_dir):
                return ver_dir
        return None
    except PermissionError:
        return None


def _find_in_portable_wildcard() -> Path | None:
    """Search drive roots for ``CodexPortable/versions/*/`` directories."""
    for drive in _get_fixed_drives():
        result = _find_in_versions_dir(drive / "CodexPortable")
        if result is not None:
            return result
    return None


def _get_fixed_drives() -> list[Path]:
    """Return ``Path`` entries for local fixed drives (``C:\\``, ``D:\\``, …)."""
    drives: list[Path] = []
    try:
        import ctypes as _ctypes

        buf = _ctypes.create_unicode_buffer(260)
        _ctypes.windll.kernel32.GetLogicalDriveStringsW(260, buf)
        for s in buf.value.split("\x00"):
            s = s.strip()
            if not s:
                continue
            try:
                drive_type = _ctypes.windll.kernel32.GetDriveTypeW(s)
                # DRIVE_FIXED = 3
                if drive_type == 3:
                    drives.append(Path(s.rstrip("\\")))
            except (OSError, RuntimeError):
                pass
    except (ImportError, AttributeError, OSError):
        # Fallback: try common drive letters
        for letter in "CDEFGH":
            p = Path(f"{letter}:/")
            if p.is_dir():
                drives.append(p)
    return drives or [Path("C:/")]


def _find_on_path() -> Path | None:
    """Search ``PATH`` for ``Codex.exe`` and return its parent directory."""
    from shutil import which

    exe_path = which("Codex.exe")
    if exe_path is None:
        return None
    parent = Path(exe_path).parent
    return parent if validate_codex_install(parent) else None


def _asar_has_webview(asar_path: Path) -> bool:
    """Check whether an ASAR archive contains a ``webview`` directory.

    Reads the JSON header embedded in the ASAR file and searches for
    the ``"webview"`` key.  Pure Python — no ``npx`` / ``asar`` CLI
    needed.

    The ASAR filesystem header is a hierarchical JSON tree where each
    directory is an object with a ``"files"`` key.  We do a cheap
    in-string search for ``"webview"`` which is reliable because the
    only place a bare ASCII ``"webview"`` occurs in the header is as a
    directory entry key.
    """
    try:
        with asar_path.open("rb") as f:
            # ASAR header: uint32 size, uint32 header_size,
            #              uint32, uint32 json_size
            header = f.read(16)
            if len(header) < 16:
                return False
            _size, _hdr_sz, _, json_size = struct.unpack("<4I", header)
            if json_size > 10 * 1024 * 1024:  # sanity cap: 10 MB
                return False
            json_data = f.read(json_size)
            if len(json_data) < json_size:
                return False
    except (OSError, struct.error, RuntimeError):
        return False

    # Cheap in-string check for the JSON key "webview".
    # In the ASAR filesystem header every directory entry is a JSON
    # object key, so a bare `"webview"` appearing in the header means
    # there is a webview directory at some level of the hierarchy.
    return b'"webview"' in json_data


# ---------------------------------------------------------------------------
# Process lifecycle
# ---------------------------------------------------------------------------


def quit_codex_app_windows(force: bool = True) -> bool:
    """Kill all ``Codex.exe`` processes via ``taskkill``.

    Parameters
    ----------
    force:
        If ``True`` (default), use ``taskkill /F`` for forceful termination.
        If ``False``, send a graceful terminate request instead.

    Returns
    -------
    ``True`` if at least one ``Codex.exe`` process was killed.
    ``False`` if Codex was not running or if an error occurred.

    Notes
    -----
    - ``taskkill`` exit code 0 means at least one process was terminated.
    - Exit code 1 with ``not found`` in stderr/stdout means no matching
      processes were running.
    - All other exit codes are treated as non-fatal errors (warning
      printed, ``False`` returned).
    - ``subprocess.TimeoutExpired`` and ``FileNotFoundError`` are handled
      gracefully.
    """
    cmd = ["taskkill", "/IM", "Codex.exe"]
    if force:
        cmd.append("/F")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        print("Warning: taskkill timed out while trying to kill Codex.exe")
        return False
    except FileNotFoundError:
        print("Warning: taskkill not found (not on Windows?)")
        return False

    if result.returncode == 0:
        # Exit code 0 -> at least one process was killed.
        return True

    # Check both stdout and stderr for the "not found" signal that
    # indicates Codex simply wasn't running.  Windows locale can affect
    # the exact message, so we match on several common substrings.
    combined = (result.stdout + " " + result.stderr).lower()
    locale_tokens = (
        "not found",
        "introuvable",  # French
        "nicht gefunden",  # German
        "no se encuentra",  # Spanish
        "non trovato",  # Italian
        "nao encontrado",  # Portuguese (also catches "não encontrado")
        "no matching",
        "enum",  # Partial match for "enum" in some locale error dumps
    )
    if any(token in combined for token in locale_tokens):
        return False
    # Exit code 128 with a message mentioning the process name also
    # indicates "not found" on some locale/Windows-version combos.
    if result.returncode == 128 and "codex.exe" in combined:
        return False

    # Unexpected error -- warn but don't crash.
    msg = result.stderr.strip() or result.stdout.strip()
    print(f"Warning: taskkill returned exit code {result.returncode}: {msg}")
    return False


def launch_codex_app_windows(codex_exe: Path) -> subprocess.Popen[bytes] | None:
    """Launch ``Codex.exe`` as a detached background process.

    Parameters
    ----------
    codex_exe:
        Absolute or relative path to ``Codex.exe``.

    Returns
    -------
    A :class:`subprocess.Popen` handle for the launched process, or
    ``None`` if launching failed (path not found, access denied, etc.).

    Notes
    -----
    - Uses ``subprocess.DETACHED_PROCESS`` (``0x00000008``) so the child
      process survives the parent (CLI) exit.
    - Both ``stdout`` and ``stderr`` are redirected to ``DEVNULL`` to
      avoid inheriting the console.
    - On error a warning is printed but no exception is raised.
    """
    try:
        proc = subprocess.Popen(
            [str(codex_exe)],
            close_fds=True,
            creationflags=subprocess.DETACHED_PROCESS,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc
    except Exception as exc:
        print(f"Warning: failed to launch Codex ({codex_exe}): {exc}")
        return None


def update_app_asar_integrity_windows(app_asar_path: Path, install_path: Path) -> None:
    """
    Update ASAR integrity metadata on Windows.

    Phase 0 investigation (Codex build 26.616.4196.0) found NO ASAR integrity
    validation on Windows portable builds:
    - No app.asar.integrity.json file present
    - No ELECTRON_ASAR_INTEGRITY compiled into Codex.exe
    - Codex.exe is not Authenticode signed
    - No JS-level integrity checking code in the bundles

    Therefore this is a no-op for v1. If future Codex Desktop builds add
    ASAR integrity on Windows, this function should be updated to:
    1. Find the integrity file (likely app.asar.integrity.json)
    2. Compute the SHA-256 header hash of the new app.asar
    3. Write the updated hash to the integrity file
    """
    msg = (
        f"Windows ASAR integrity: no integrity validation detected "
        f"on this build (no-op). asar={app_asar_path}, install={install_path}"
    )
    print(msg)
    logger.info(msg)
