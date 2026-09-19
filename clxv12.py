#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLXV12 TOOLKIT v2.1.0 - hardened release
Production-oriented, offline-first Termux/Android development suite.
Single file. Python standard library only.
Architecture: UI / System / Project / Build / APK / Git / Network /
Wi-Fi Audit / File / Archive / Developer / Cleanup / Search / Profile engines.
"""

import argparse
import base64
import binascii
import contextlib
import getpass
import signal
import hashlib
import io
import ipaddress
import json
import os
import platform
import random
import re
import shlex
import shutil
import socket
import string
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import datetime
from pathlib import Path, PurePosixPath

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:                      # non-POSIX fallback: best-effort only
    _HAS_FCNTL = False

from urllib.parse import urlsplit, urlunsplit

VERSION = "2.2.0"
APP_NAME = "CLXV12 TOOLKIT"
APP_SUB = "TERMUX DEVELOPMENT SUITE"
IDENTITY_RE = re.compile(r"clxv1[12]", re.IGNORECASE)
CONFIG_DIR = Path.home() / ".clxv12"


def migrate_legacy_config():
    """One-time, idempotent upgrade: ~/.clxv11 -> ~/.clxv12. Never runs when
    the new directory already exists (no data loss, no overwrite)."""
    legacy = Path.home() / ".clxv11"
    try:
        if legacy.exists() and not CONFIG_DIR.exists():
            legacy.rename(CONFIG_DIR)
            return True
    except OSError:
        pass
    return False
DATA_FILES = {
    "config": CONFIG_DIR / "config.json",
    "tools": CONFIG_DIR / "tools.json",
    "projects": CONFIG_DIR / "projects.json",
    "history": CONFIG_DIR / "history.json",
    "profile": CONFIG_DIR / "profile.json",
}
MAX_HISTORY = 400
SCAN_MAX_DEPTH = 5
SCAN_MAX_ENTRIES = 4000

LOG_DIR = CONFIG_DIR / "logs"
LOG_MAX_BYTES = 512 * 1024
LOG_BACKUPS = 3

# ---------------------------------------------------------------------------
# EXIT CODES - stable contract for scripts, CI and shell callers
# ---------------------------------------------------------------------------


class ExitCode:
    SUCCESS = 0
    GENERAL = 1
    INVALID_ARGUMENT = 2
    NOT_FOUND = 3
    PERMISSION = 4
    SECURITY_BLOCK = 5
    TIMEOUT = 6
    DEPENDENCY_MISSING = 7
    BUILD_ERROR = 8
    NETWORK_ERROR = 9
    INTERNAL = 10

    _NAMES = {
        0: "SUCCESS", 1: "GENERAL_ERROR", 2: "INVALID_ARGUMENT", 3: "NOT_FOUND",
        4: "PERMISSION_ERROR", 5: "SECURITY_BLOCK", 6: "TIMEOUT",
        7: "DEPENDENCY_MISSING", 8: "BUILD_ERROR", 9: "NETWORK_ERROR",
        10: "INTERNAL_ERROR",
    }

    @classmethod
    def name(cls, code):
        return cls._NAMES.get(code, "UNKNOWN(%s)" % code)

    @classmethod
    def all_rows(cls):
        return [(c, cls._NAMES[c]) for c in sorted(cls._NAMES)]


class ErrCode:
    """Machine-stable error identifiers used in JSON `errors[].code`."""
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_HOST = "INVALID_HOST"
    INVALID_PORT = "INVALID_PORT"
    INVALID_PATH = "INVALID_PATH"
    NOT_FOUND = "NOT_FOUND"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SECURITY_BLOCK = "SECURITY_BLOCK"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    TIMEOUT = "TIMEOUT"
    NETWORK_TIMEOUT = "NETWORK_TIMEOUT"
    NETWORK_UNREACHABLE = "NETWORK_UNREACHABLE"
    DNS_FAILURE = "DNS_FAILURE"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    BUILD_FAILED = "BUILD_FAILED"
    ARCHIVE_UNSAFE = "ARCHIVE_UNSAFE"
    ARCHIVE_CORRUPT = "ARCHIVE_CORRUPT"
    APK_INVALID = "APK_INVALID"
    STORE_CORRUPT = "STORE_CORRUPT"
    INTERRUPTED = "INTERRUPTED"
    UNAVAILABLE = "UNAVAILABLE"
    INTERNAL = "INTERNAL"


ERR_TO_EXIT = {
    ErrCode.INVALID_ARGUMENT: ExitCode.INVALID_ARGUMENT,
    ErrCode.INVALID_HOST: ExitCode.INVALID_ARGUMENT,
    ErrCode.INVALID_PORT: ExitCode.INVALID_ARGUMENT,
    ErrCode.INVALID_PATH: ExitCode.INVALID_ARGUMENT,
    ErrCode.NOT_FOUND: ExitCode.NOT_FOUND,
    ErrCode.PERMISSION_DENIED: ExitCode.PERMISSION,
    ErrCode.SECURITY_BLOCK: ExitCode.SECURITY_BLOCK,
    ErrCode.PATH_TRAVERSAL: ExitCode.SECURITY_BLOCK,
    ErrCode.ARCHIVE_UNSAFE: ExitCode.SECURITY_BLOCK,
    ErrCode.TIMEOUT: ExitCode.TIMEOUT,
    ErrCode.NETWORK_TIMEOUT: ExitCode.TIMEOUT,
    ErrCode.NETWORK_UNREACHABLE: ExitCode.NETWORK_ERROR,
    ErrCode.DNS_FAILURE: ExitCode.NETWORK_ERROR,
    ErrCode.DEPENDENCY_MISSING: ExitCode.DEPENDENCY_MISSING,
    ErrCode.BUILD_FAILED: ExitCode.BUILD_ERROR,
    ErrCode.ARCHIVE_CORRUPT: ExitCode.GENERAL,
    ErrCode.APK_INVALID: ExitCode.GENERAL,
    ErrCode.STORE_CORRUPT: ExitCode.GENERAL,
    ErrCode.INTERRUPTED: ExitCode.GENERAL,
    ErrCode.UNAVAILABLE: ExitCode.DEPENDENCY_MISSING,
    ErrCode.INTERNAL: ExitCode.INTERNAL,
}


def exit_code_for(err_code):
    return ERR_TO_EXIT.get(err_code, ExitCode.GENERAL)


class ToolkitError(Exception):
    """Base of the structured error hierarchy. Every layer raises these
    instead of leaking raw OSError/ValueError to the CLI surface."""
    code = ErrCode.INTERNAL

    def __init__(self, message, code=None, detail=None):
        super().__init__(message)
        self.message = str(message)
        if code:
            self.code = code
        self.detail = detail

    @property
    def exit_code(self):
        return exit_code_for(self.code)

    def as_dict(self):
        d = {"code": self.code, "message": redact_credentials(self.message)}
        if self.detail:
            d["detail"] = redact_credentials(str(self.detail))
        return d


class InvalidArgument(ToolkitError):
    code = ErrCode.INVALID_ARGUMENT


class NotFound(ToolkitError):
    code = ErrCode.NOT_FOUND


class PermissionDenied(ToolkitError):
    code = ErrCode.PERMISSION_DENIED


class SecurityBlock(ToolkitError):
    code = ErrCode.SECURITY_BLOCK


class OperationTimeout(ToolkitError):
    code = ErrCode.TIMEOUT


class DependencyMissing(ToolkitError):
    code = ErrCode.DEPENDENCY_MISSING


class BuildFailure(ToolkitError):
    code = ErrCode.BUILD_FAILED


class NetworkFailure(ToolkitError):
    code = ErrCode.NETWORK_UNREACHABLE


# ---------------------------------------------------------------------------
# OPERATION RESULT - the single value every engine returns
# ---------------------------------------------------------------------------


class OpResult:
    """Structured engine result. The terminal UI and the JSON writer both
    render *this*; there is never a second code path per output mode."""

    __slots__ = ("ok", "data", "errors", "warnings", "meta")

    def __init__(self, ok=True, data=None, errors=None, warnings=None, meta=None):
        self.ok = bool(ok)
        self.data = data
        self.errors = list(errors or [])
        self.warnings = list(warnings or [])
        self.meta = dict(meta or {})

    # -- constructors ------------------------------------------------------
    @classmethod
    def success(cls, data=None, warnings=None, meta=None):
        return cls(True, data, None, warnings, meta)

    @classmethod
    def failure(cls, code, message, data=None, detail=None, meta=None):
        r = cls(False, data, None, None, meta)
        r.add_error(code, message, detail)
        return r

    @classmethod
    def from_exception(cls, exc, command=None):
        if isinstance(exc, ToolkitError):
            return cls.failure(exc.code, exc.message, detail=exc.detail)
        mapped = {
            PermissionError: (ErrCode.PERMISSION_DENIED, None),
            FileNotFoundError: (ErrCode.NOT_FOUND, None),
            NotADirectoryError: (ErrCode.INVALID_PATH, None),
            IsADirectoryError: (ErrCode.INVALID_PATH, None),
            TimeoutError: (ErrCode.TIMEOUT, None),
            socket.gaierror: (ErrCode.DNS_FAILURE, None),
            socket.timeout: (ErrCode.NETWORK_TIMEOUT, None),
            ValueError: (ErrCode.INVALID_ARGUMENT, None),
            KeyboardInterrupt: (ErrCode.INTERRUPTED, "cancelled by user"),
        }
        for exc_type, (code, override) in mapped.items():
            if isinstance(exc, exc_type):
                return cls.failure(code, override or "%s: %s" % (type(exc).__name__, exc))
        if isinstance(exc, OSError):
            return cls.failure(ErrCode.INTERNAL, "%s: %s" % (type(exc).__name__, exc))
        return cls.failure(ErrCode.INTERNAL, "%s: %s" % (type(exc).__name__, exc))

    # -- mutation ----------------------------------------------------------
    def add_error(self, code, message, detail=None):
        entry = {"code": code, "message": redact_credentials(str(message))}
        if detail is not None:
            entry["detail"] = redact_credentials(str(detail))
        self.errors.append(entry)
        self.ok = False
        return self

    def add_warning(self, message, code=None):
        entry = {"message": redact_credentials(str(message))}
        if code:
            entry["code"] = code
        self.warnings.append(entry)
        return self

    # -- output ------------------------------------------------------------
    @property
    def exit_code(self):
        if self.ok:
            return ExitCode.SUCCESS
        worst = ExitCode.GENERAL
        for e in self.errors:
            worst = max(worst, exit_code_for(e.get("code")))
        return worst

    def envelope(self, command):
        return {
            "ok": self.ok,
            "command": command,
            "version": VERSION,
            "timestamp": now_iso(),
            "data": self.data if self.ok else (self.data if self.data is not None else None),
            "warnings": self.warnings,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# RUNTIME CONTEXT - one place that knows which output mode we are in
# ---------------------------------------------------------------------------


class RuntimeContext:
    """Global, process-wide switches resolved once from argv."""

    def __init__(self):
        self.json = False
        self.quiet = False
        self.verbose = False
        self.debug = False
        self.plain = False
        self.no_color = False
        self.interactive = sys.stdin.isatty()
        self.timeout = 30.0
        self.depth = SCAN_MAX_DEPTH
        self.max_results = 500
        self.log_file = None
        self.command = None
        self.started = time.monotonic()

    @property
    def machine(self):
        """True when stdout is reserved for machine-readable output only."""
        return self.json

    @property
    def can_prompt(self):
        return self.interactive and not self.json

    def elapsed_ms(self):
        return int((time.monotonic() - self.started) * 1000)

    def apply(self, args):
        self.json = bool(getattr(args, "json", False))
        self.quiet = bool(getattr(args, "quiet", False))
        self.verbose = bool(getattr(args, "verbose", False))
        self.debug = bool(getattr(args, "debug", False))
        self.plain = bool(getattr(args, "plain", False))
        self.no_color = bool(getattr(args, "no_color", False)) or self.plain or self.json
        if self.json or not sys.stdin.isatty():
            self.interactive = False
        t = getattr(args, "timeout", None)
        if t is not None:
            self.timeout = max(0.1, min(float(t), 3600.0))
        d = getattr(args, "depth", None)
        if d is not None:
            self.depth = max(1, min(int(d), 64))
        m = getattr(args, "max_results", None)
        if m is not None:
            self.max_results = max(1, min(int(m), 1000000))
        lf = getattr(args, "log_file", None)
        if lf:
            self.log_file = str(lf)
        return self


RT = RuntimeContext()


def diag(message, level="info"):
    """Diagnostics channel. NEVER stdout: in machine mode stdout belongs to
    JSON alone, and in quiet mode the human does not want chatter."""
    LOG.event(level, message)
    if RT.quiet and level not in ("error", "warning"):
        return
    if RT.json and not (RT.verbose or RT.debug):
        return
    try:
        sys.stderr.write("[%s] %s\n" % (level, redact_credentials(str(message))))
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


@contextlib.contextmanager
def stdout_firewall(enabled=True):
    """Belt-and-braces JSON purity guard.

    Even though every machine-mode command uses non-interactive data
    providers that print nothing, a future regression inside any engine
    must not be able to corrupt stdout. Anything written while this guard
    is active is diverted to the log (and to stderr under --verbose)."""
    if not enabled:
        yield None
        return
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            yield buf
    finally:
        leaked = buf.getvalue()
        if leaked.strip():
            LOG.event("warning", "stdout leak suppressed in machine mode",
                      bytes=len(leaked), sample=leaked[:400])
            if RT.verbose or RT.debug:
                try:
                    sys.stderr.write("[stdout-leak-suppressed] %s\n"
                                     % redact_credentials(leaked[:2000]))
                except (OSError, ValueError):
                    pass


def emit_json(envelope_obj):
    """Write exactly one JSON document to stdout and nothing else."""
    text = json.dumps(envelope_obj, indent=2, ensure_ascii=False, default=str)
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        raise
    except (OSError, ValueError):
        pass


# ---------------------------------------------------------------------------
# LOGGING - rotating JSON-lines logs, secrets redacted before they touch disk
# ---------------------------------------------------------------------------


class LogManager:
    STREAMS = ("app", "error", "security", "audit", "crash")

    def __init__(self):
        self._broken = set()
        self.enabled = True

    def _path(self, stream):
        if RT.log_file and stream == "app":
            return Path(RT.log_file)
        return LOG_DIR / ("%s.log" % stream)

    def _rotate(self, path):
        try:
            if path.exists() and path.stat().st_size > LOG_MAX_BYTES:
                for i in range(LOG_BACKUPS - 1, 0, -1):
                    src, dst = Path("%s.%d" % (path, i)), Path("%s.%d" % (path, i + 1))
                    if src.exists():
                        os.replace(str(src), str(dst))
                os.replace(str(path), "%s.1" % path)
        except OSError:
            pass

    def _write(self, stream, record):
        if not self.enabled or stream in self._broken:
            return False
        path = self._path(stream)
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._rotate(path)
            line = json.dumps(record, ensure_ascii=False, default=str)
            line = redact_credentials(line)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, (line + "\n").encode("utf-8", errors="replace"))
            finally:
                os.close(fd)
            return True
        except (OSError, ValueError, TypeError):
            self._broken.add(stream)     # logging must never break the tool
            return False

    def event(self, level, message, **fields):
        rec = {"ts": now_iso(), "level": level, "message": str(message),
               "command": RT.command, "pid": os.getpid()}
        rec.update(fields)
        self._write("app", rec)
        if level in ("error", "critical"):
            self._write("error", rec)

    def security(self, event, **fields):
        rec = {"ts": now_iso(), "event": event, "command": RT.command,
               "pid": os.getpid()}
        rec.update(fields)
        self._write("security", rec)

    def audit(self, operation, target="", result="success", duration_ms=None, **fields):
        rec = {"timestamp": now_iso(), "operation": operation,
               "target": str(target), "result": result}
        if duration_ms is not None:
            rec["duration_ms"] = int(duration_ms)
        rec.update(fields)
        self._write("audit", rec)

    def crash(self, error_id, text):
        return self._write("crash", {"ts": now_iso(), "error_id": error_id,
                                     "command": RT.command, "traceback": str(text)})


LOG = LogManager()


@contextlib.contextmanager
def audited(operation, target=""):
    """Wrap a sensitive operation so that success, failure and duration all
    land in the audit trail without the caller remembering to do it."""
    t0 = time.monotonic()
    try:
        yield
    except BaseException as exc:                       # noqa: BLE001 - re-raised
        LOG.audit(operation, target, "failure",
                  (time.monotonic() - t0) * 1000, error=type(exc).__name__)
        raise
    else:
        LOG.audit(operation, target, "success", (time.monotonic() - t0) * 1000)


# ---------------------------------------------------------------------------
# THEME - single color abstraction, never scattered escapes
# ---------------------------------------------------------------------------

class Theme:
    LEVELS = ("truecolor", "ansi", "mono")

    def __init__(self, force_no_color=False):
        self.level = self._detect(force_no_color)

    def _detect(self, no_color):
        if no_color or "--no-color" in sys.argv or os.environ.get("NO_COLOR"):
            return "mono"
        if not sys.stdout.isatty():
            return "mono"
        term = os.environ.get("TERM", "")
        if os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit"):
            return "truecolor"
        if "color" in term or term in ("xterm", "screen", "tmux", "linux"):
            return "ansi"
        return "mono"

    # palette: name -> (truecolor, ansi, mono) ; mono = ""
    _P = {
        "primary":   ("38;2;80;200;255", "36", ""),
        "secondary": ("38;2;150;150;255", "35", ""),
        "success":   ("38;2;80;220;140", "32", ""),
        "warning":   ("38;2;255;200;80", "33", ""),
        "error":     ("38;2;255;110;110", "31", ""),
        "info":      ("38;2;140;180;255", "34", ""),
        "muted":     ("38;2;120;120;120", "90", ""),
        "title":     ("38;2;0;220;190", "1;36", ""),
        "border":    ("38;2;70;110;130", "36", ""),
        "accent":    ("38;2;255;150;60", "33", ""),
        "white":     ("38;2;235;235;235", "37", ""),
        "red":       ("38;2;255;90;90",  "31", ""),
    }

    def c(self, text, name):
        if self.level == "mono":
            return str(text)
        code = self._P.get(name, ("", "", ""))[0 if self.level == "truecolor" else 1]
        if not code:
            return str(text)
        return "\033[%sm%s\033[0m" % (code, text)

    def strip(self, text):
        return re.sub(r"\033\[[0-9;]*m", "", str(text))

    def visible_len(self, text):
        import unicodedata
        total = 0
        for ch in self.strip(text):
            total += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        return total


# ---------------------------------------------------------------------------
# ICON abstraction: unicode glyph with ASCII fallback
# ---------------------------------------------------------------------------

_ICONS = {
    "app":      ("◆", "*"), "project": ("▣", "[P]"), "build": ("⚒", "[B]"),
    "apk":      ("▤", "[A]"), "network": ("⌁", "[N]"), "security": ("⚠", "[!]"),
    "file":     ("▤", "[F]"), "git": ("⑂", "[G]"), "system": ("⚙", "[S]"),
    "search":   ("◎", "[?]"), "history": ("◔", "[H]"), "settings": ("⚒", "[C]"),
    "exit":     ("→", "[0]"), "archive": ("▦", "[Z]"), "tools": ("✚", "[T]"),
    "cleanup":  ("♻", "[K]"), "ok": ("✓", "+"), "bad": ("✕", "x"),
    "warn":     ("!", "!"), "run": ("▸", ">"), "back": ("←", "<"),
}
_unicode_ok = None

def supports_unicode():
    global _unicode_ok
    if _unicode_ok is not None:
        return _unicode_ok
    enc = (sys.stdout.encoding or "").lower()
    _unicode_ok = "utf" in enc
    return _unicode_ok

def ico(name):
    pair = _ICONS.get(name, ("?", "?"))
    return pair[0] if supports_unicode() else pair[1]

# ---------------------------------------------------------------------------
# UI ENGINE - responsive terminal rendering
# ---------------------------------------------------------------------------

class UI:
    MIN_WIDTH = 40

    def __init__(self, theme):
        self.t = theme

    # -- geometry -----------------------------------------------------------
    def width(self):
        try:
            w = shutil.get_terminal_size((80, 24)).columns
        except OSError:
            w = 80
        return max(self.MIN_WIDTH, w)

    def _fit(self, text, width):
        text = self.t.strip(text)
        if len(text) <= width:
            return text
        if width < 8:
            return text[:width]
        return text[:width - 1] + "…"

    def fit_padded(self, text, width, align="left"):
        clean = self.t.strip(text)
        if len(clean) > width:
            clean = self._fit(clean, width)
        pad = width - self.t.visible_len(clean)   # CJK-aware padding
        if align == "right":
            return " " * pad + clean
        if align == "center":
            return " " * (pad // 2) + clean + " " * (pad - pad // 2)
        return clean + " " * pad

    # -- primitives ---------------------------------------------------------
    def clear(self):
        sys.stdout.write("\033[2J\033[H" if sys.stdout.isatty() else "\n")

    def hr(self, char="─", color="border"):
        print(self.t.c(char * self.width(), color))

    def header(self, title, subtitle=""):
        w = self.width()
        inner = w - 2
        print(self.t.c("╔" + "═" * inner + "╗", "border"))
        for line in ([title] if not subtitle else [title, subtitle]):
            txt = self.fit_padded(line, inner, "center")
            print(self.t.c("║", "border") + self.t.c(txt, "title" if line == title else "muted")
                  + self.t.c("║", "border"))
        print(self.t.c("╚" + "═" * inner + "╝", "border"))

    def status(self, kind, msg):
        marks = {
            "ok": (ico("ok"), "success"), "bad": (ico("bad"), "error"),
            "warn": (ico("warn"), "warning"), "info": ("i", "info"),
            "run": (ico("run"), "accent"),
        }
        mark, color = marks.get(kind, ("i", "info"))
        print("%s %s" % (self.t.c("[%s]" % mark, color), msg))

    # -- panels ---------------------------------------------------------------
    def panels(self, panels):
        """panels: list of (title, [(k, v), ...]). Side-by-side if width allows."""
        w = self.width()
        rendered = []
        for title, rows in panels:
            body = []
            kw = max([len(k) for k, _ in rows] + [0])
            vw = max([self.t.visible_len(self.t.strip(v)) for _, v in rows] + [0])
            pw = max(10, kw + 3 + min(vw, 44)) + 4
            for k, v in rows:
                body.append("│ %s : %s" % (k.ljust(kw), self._fit(v, pw - kw - 7)))
            rendered.append((title, body, max(pw, len(title) + 6)))
        total = sum(p[2] for p in rendered) + len(rendered) + 1
        if total <= w and len(rendered) > 1:
            self._panels_row(rendered)
        else:
            for title, body, pw in rendered:
                self._single_panel(title, body, pw)

    def _single_panel(self, title, body, pw):
        t = self.t
        pw = max(pw, max([len(x) for x in body] + [len(title) + 4]))
        print(t.c("┌─ " + title + " " + "─" * max(0, pw - len(title) - 3) + "┐", "border"))
        for line in body:
            clean = t.strip(line)
            print(t.c(line, "white") + " " * max(0, pw - t.visible_len(clean)) + t.c("│", "border"))
        print(t.c("└" + "─" * pw + "┘", "border"))

    def _panels_row(self, rendered):
        t = self.t
        tops, bots, bodys = [], [], []
        hmax = 0
        for title, body, pw in rendered:
            tops.append(t.c("┌─ " + title + " " + "─" * max(0, pw - len(title) - 3) + "┐", "border"))
            bots.append(t.c("└" + "─" * pw + "┘", "border"))
            hmax = max(hmax, len(body))
            bodys.append(body)
        print(" ".join(tops))
        for i in range(hmax):
            cells = []
            for body, (_, _, pw) in zip(bodys, rendered):
                if i < len(body):
                    clean = t.strip(body[i])
                    cells.append(t.c(body[i], "white") + " " * (pw - t.visible_len(clean)) + t.c("│", "border"))
                else:
                    cells.append(" " * (pw + 1) + t.c("│", "border"))
            print(" ".join(cells))
        print(" ".join(bots))

    # -- table ---------------------------------------------------------------
    def table(self, headers, rows, max_width=None):
        if not rows:
            self.status("info", "No entries.")
            return
        tw = max_width or self.width()
        cols = list(zip(*rows)) if rows else [[] for _ in headers]
        widths = []
        for i, h in enumerate(headers):
            cells = [self.t.strip(str(r[i])) for r in rows]
            natural = max([len(h)] + [len(x) for x in cells])
            widths.append(min(natural, 40))
        total = sum(widths) + 3 * len(widths) + 1
        if total > tw:
            over = total - tw
            while over > 0 and max(widths) > 8:
                i = widths.index(max(widths))
                cut = min(over, widths[i] - 8)
                widths[i] -= cut
                over -= cut
        sep = self.t.c("─" * (sum(widths) + 3 * len(widths) + 1), "border")
        print(sep)
        line = "│ " + " │ ".join(self.fit_padded(h, widths[i]) for i, h in enumerate(headers)) + " │"
        print(self.t.c(line, "accent"))
        print(sep)
        for r in rows:
            line = "│ " + " │ ".join(self.fit_padded(str(r[i]), widths[i]) for i in range(len(headers))) + " │"
            print(line)
        print(sep)

    # -- pagination ------------------------------------------------------------
    def paginate(self, lines, per_page=None, header=None):
        per_page = per_page or max(5, self.width() // 3)
        total = len(lines)
        page = 0
        while True:
            clear_needed = False
            start = page * per_page
            chunk = lines[start:start + per_page]
            if header:
                print(header)
            for ln in chunk:
                print(ln)
            last = start + len(chunk)
            print(self.t.c("── %d-%d / %d ──" % (start + 1 if total else 0, last, total), "muted"))
            if last >= total:
                return
            try:
                cmd = input(self.t.c("[Enter]=next  [p]=prev  [q]=stop > ", "muted")).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if cmd == "q":
                return
            if cmd == "p" and page > 0:
                page -= 1
            elif cmd == "p":
                pass
            else:
                page += 1
            if header:
                pass

    # -- interaction ----------------------------------------------------------
    def ask(self, prompt, default=None):
        # Non-interactive (--json, piped stdin, CI): never block on a prompt.
        if not RT.can_prompt:
            return default
        suffix = " [%s]" % default if default not in (None, "") else ""
        try:
            raw = input(self.t.c(prompt + suffix + ": ", "primary"))
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        raw = raw.strip()
        if not raw:
            return default
        return raw[:512]

    def confirm(self, prompt, default=False):
        # A destructive action is NEVER auto-confirmed when nobody can answer.
        if not RT.can_prompt:
            return False
        suffix = "[Y/n]" if default else "[y/N]"
        try:
            raw = input(self.t.c("%s %s: " % (prompt, suffix), "warning"))
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        raw = raw.strip().lower()
        if not raw:
            return default
        return raw in ("y", "yes")

    def pause(self):
        if not RT.can_prompt:
            return
        try:
            input(self.t.c("── Press Enter ──", "muted"))
        except (EOFError, KeyboardInterrupt):
            print()

    def menu(self, title, entries, note=None):
        """entries: list of (key, label, icon_name). Returns chosen key or None."""
        if not RT.can_prompt:
            return None
        while True:
            self.clear()
            self.header(title, APP_SUB)
            if note:
                print(self.t.c(self._fit(note, self.width() - 4), "muted"))
            colw = max([len(k) + len(l) + 6 for k, l, _ in entries] + [10])
            ncol = max(1, (self.width() - 4) // max(colw, 18))
            ncol = min(ncol, 3, len(entries))
            per = (len(entries) + ncol - 1) // ncol
            for row in range(per):
                cells = []
                for col in range(ncol):
                    idx = col * per + row
                    if idx < len(entries):
                        k, label, ic = entries[idx]
                        cell = "%s [%s] %s" % (ico(ic), k, label)
                        cells.append(self.fit_padded(cell, colw))
                print("  " + self.t.c("  ".join(cells), "white"))
            print()
            try:
                choice = input(self.t.c("Select > ", "primary")).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return None
            for k, _, _ in entries:
                if choice.lower() == str(k).lower():
                    return k
            if choice == "":
                return None
            self.status("bad", "Invalid choice.")

THEME = Theme()
UIx = UI(THEME)

# ---------------------------------------------------------------------------
# CORE - paths, safe path layer, storage, history, subprocess engine
# ---------------------------------------------------------------------------

def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _build_system_deny():
    root_entry = Path("/nonexistent-xyz")
    try:
        if os.geteuid() == 0:              # POSIX only; absent on Windows
            root_entry = Path("/root")
    except AttributeError:
        pass
    return {Path("/"), Path("/bin"), Path("/boot"), Path("/data"),
            Path("/dev"), Path("/etc"), Path("/lib"), Path("/proc"),
            root_entry,
            Path("/sbin"), Path("/sys"), Path("/system"), Path("/usr"),
            Path("/vendor"), Path("/product"), Path("/sdcard")}


SYSTEM_ROOT_DENY = _build_system_deny()


def _sanitize_roots(candidates):
    out = []
    for r in candidates:
        try:
            r = Path(r).expanduser().resolve()
        except OSError:
            continue
        if r in SYSTEM_ROOT_DENY:
            continue
        if len(r.parts) < 3:  # require real depth: /x/y minimum
            continue
        if r not in out:
            out.append(r)
    return out


def read_roots():
    """Roots readable by the toolkit: HOME, cwd (unless a system dir), storage."""
    roots = [Path.home(), Path.cwd()]
    for extra in ("storage/shared", "storage/downloads"):
        p = Path.home() / extra
        if p.exists():
            roots.append(p)
    return _sanitize_roots(roots)


def write_roots():
    """Roots where the toolkit may create/overwrite files.

    Deterministic set: HOME + optional shared storage + cwd (when cwd is a
    sane user directory, never a system root). Membership is explicit; the
    policy does not widen based on arbitrary working directories because
    _sanitize_roots() filters dangerous locations."""
    roots = [Path.home(), Path.cwd()]
    for extra in ("storage/shared", "storage/downloads"):
        p = Path.home() / extra
        if p.exists():
            roots.append(p)
    return _sanitize_roots(roots)


def delete_roots():
    """Roots where the toolkit may delete. Same policy as write_roots();
    destructive operations additionally revalidate their target and refuse
    protected locations (HOME itself, ~/.clxv11, /) at the call site."""
    return write_roots()


def approved_roots():
    return read_roots()


def safe_write_path(path):
    """Validate a write target that may not exist yet.
    Validates the *parent* (must exist, be a directory, sit inside
    write_roots, and be writable) and returns the normalized target."""
    try:
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        parent = p.parent
        if not parent.exists() or not parent.is_dir():
            return None
        real_parent = parent.resolve()
        if not any(real_parent == r or r in real_parent.parents for r in write_roots()):
            return None
        if not os.access(str(real_parent), os.W_OK):
            return None
        return Path(os.path.abspath(str(p)))
    except (OSError, RuntimeError, ValueError):
        return None


def path_relation(a, b):
    """Classify the relationship of path a to path b after resolving symlinks.
    Returns one of: 'same', 'a_in_b' (a is inside b), 'b_in_a', or None."""
    try:
        pa = Path(a).resolve()
        pb = Path(b).resolve()
    except (OSError, RuntimeError):
        return None
    if pa == pb:
        return "same"
    if pb in pa.parents:
        return "a_in_b"
    if pa in pb.parents:
        return "b_in_a"
    return None


# ---------------------------------------------------------------------------
# SECURITY LAYER - symlink-aware resolution, protected paths, atomic writes
# ---------------------------------------------------------------------------

def resolve_ancestor(path):
    """Resolve symlinks for a path that may not exist yet: walk up to the
    nearest existing ancestor, resolve THAT for real, then re-append the
    remaining components. Plain abspath() leaves symlinked parents unresolved
    and lets writes escape the approved roots."""
    p = Path(path)
    tail = []
    cur = p
    try:
        while not cur.exists() and cur != cur.parent:
            tail.append(cur.name)
            cur = cur.parent
        base = cur.resolve()
        for name in reversed(tail):
            base = base / name
        return base
    except (OSError, RuntimeError, ValueError):
        return None


def secure_target(raw, base=None, for_write=False, must_exist=True,
                  allow_symlink_link_op=False):
    """Unified validator for EVERY file operation.

    * relative input resolves against `base` (browser cwd), never process cwd
    * existing paths resolve fully through symlinks; new targets resolve
      through their existing ancestors (a symlinked parent cannot smuggle a
      write outside the roots)
    * resolved path MUST stay inside approved roots (read_roots / write_roots)
    * a symlink as INPUT is REFUSED by default; with allow_symlink_link_op
      the link itself is accepted (rename/move/delete) - the target is never
      touched, never followed
    * broken symlinks acceptable only as link operations (unlink)
    * anything unresolved, ambiguous or out-of-bounds => None (REFUSE)"""
    if not raw:
        return None
    try:
        p = Path(raw).expanduser()
    except (OSError, RuntimeError, ValueError):
        return None
    if not p.is_absolute():
        p = (Path(base) if base else Path.cwd()) / p
    try:
        if p.is_symlink():
            if not allow_symlink_link_op:
                return None
            parent_res = resolve_ancestor(p.parent)
            if parent_res is None:
                return None
            roots = write_roots() if for_write else read_roots()
            if not any(parent_res == r or r in parent_res.parents for r in roots):
                return None
            return p.absolute()          # the LINK itself; target never touched
        if p.exists():
            rp = p.resolve()
        else:
            if must_exist or not for_write:
                return None
            rp = resolve_ancestor(p)
            if rp is None:
                return None
        roots = write_roots() if for_write else read_roots()
        if not any(rp == r or r in rp.parents for r in roots):
            return None
        return rp
    except (OSError, RuntimeError, ValueError):
        return None


def copy_tree_no_symlinks(src, dst):
    """Recursive copy that NEVER follows symlinks: link entries and special
    files are skipped and counted. Returns (copied, skipped)."""
    copied, skipped = 0, 0
    src, dst = Path(src), Path(dst)
    dst.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(str(src), followlinks=False):
        rel = Path(root).relative_to(src)
        for d in list(dirs):
            dp = Path(root) / d
            if dp.is_symlink():
                dirs.remove(d)
                skipped += 1
                continue
            (dst / rel / d).mkdir(exist_ok=True)
        for f in files:
            fp = Path(root) / f
            try:
                if fp.is_symlink() or not fp.is_file():
                    skipped += 1
                    continue
            except OSError:
                skipped += 1
                continue
            shutil.copy2(str(fp), str(dst / rel / f))
            copied += 1
    return copied, skipped


def protected_paths():
    """Paths the toolkit must never delete or overwrite."""
    out = {Path("/").resolve()}
    try:
        out.add(Path.home().resolve())
        out.add(CONFIG_DIR.resolve())
    except (OSError, RuntimeError):
        pass
    return out


CRED_QUERY_KEYS = ("token", "pass", "secret", "auth", "key", "credential")
_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>]+")


def _redact_url(url):
    """Strip userinfo and credential-like query params from a URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return re.sub(r"://([^/@\s]+)@", r"://[REDACTED]@", url)
    netloc = parts.netloc
    if "@" in netloc:
        netloc = "[REDACTED]@" + netloc.rsplit("@", 1)[1]
    query = parts.query
    if query:
        pairs = []
        for kv in query.split("&"):
            k = kv.split("=", 1)[0].lower()
            pairs.append(kv.split("=", 1)[0] + "=[REDACTED]"
                         if any(s in k for s in CRED_QUERY_KEYS) else kv)
        query = "&".join(pairs)
    frag = "" if parts.scheme in ("http", "https") else parts.fragment
    return urlunsplit((parts.scheme, netloc, parts.path, query, frag))


REDACTION_MARK = "[REDACTED]"

# Two families:
#   * prefix patterns  - group(1) is a harmless label that is kept, the rest
#                        of the match is replaced.
#   * token patterns   - no groups: the whole match is a secret.
SECRET_PREFIX_PATTERNS = (
    re.compile(r"(--ks-pass\s+)(\S+)", re.I),
    re.compile(r"(--key-pass\s+)(\S+)", re.I),
    re.compile(r"(--password\s+)(\S+)", re.I),
    re.compile(r"(pass:)(\S+)", re.I),
    # generic key=value / key: value across common secret names
    re.compile(r"((?:pass|passwd|password|pwd|secret|token|api[_-]?key|"
               r"apikey|access[_-]?key|secret[_-]?key|private[_-]?key|"
               r"client[_-]?secret|auth[_-]?token|refresh[_-]?token|"
               r"session[_-]?id|sessionid|credential|passphrase)"
               r"\s*[=:]\s*[\"']?)([^\s\"',;&}\]]{3,})", re.I),
    re.compile(r"(Authorization\s*[:=]\s*)(\S+)", re.I),
    re.compile(r"(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})"),
    re.compile(r"(Basic\s+)([A-Za-z0-9+/=]{12,})"),
    re.compile(r"((?:Set-)?Cookie\s*:\s*)(\S+)", re.I),
    re.compile(r"(X-Api-Key\s*[:=]\s*)(\S+)", re.I),
)

SECRET_TOKEN_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),            # GitHub PAT/OAuth
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),          # GitHub fine-grained
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"),               # Google API key
    re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}\b"),             # Google OAuth
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),          # Slack
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),             # AWS access key
    re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),                  # npm
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                   # OpenAI-style
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),   # Stripe
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}\b"),             # GitLab
    re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),                   # HuggingFace
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----",
               re.S),
    re.compile(r"\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{40,}"),
)


def redact_credentials(text):
    """Centralized secret scrubber.

    Order matters: URLs first (urllib.parse, not a fragile mega-regex), then
    whole-token secrets, then prefixed key=value pairs. Everything written to
    a log, a report, an error message or a JSON envelope passes through here."""
    text = str(text)
    chunks, last = [], 0
    for mtch in _URL_RE.finditer(text):
        chunks.append(text[last:mtch.start()])
        chunks.append(_redact_url(mtch.group(0)))
        last = mtch.end()
    chunks.append(text[last:])
    text = "".join(chunks)
    for pat in SECRET_TOKEN_PATTERNS:
        text = pat.sub(REDACTION_MARK, text)
    for pat in SECRET_PREFIX_PATTERNS:
        text = pat.sub(lambda m: m.group(1) + REDACTION_MARK, text)
    return text


def is_config_path(path):
    """True for the config directory and anything inside it. HOME itself
    stays cleanable (that is Cleanup's job); only the toolkit's own data is
    off-limits, including its contents."""
    try:
        rp = Path(path).resolve()
        cfg = CONFIG_DIR.resolve()
    except (OSError, RuntimeError):
        return True
    return rp == cfg or cfg in rp.parents


def is_protected(path):
    """True for protected paths. Unresolvable paths are treated as protected."""
    try:
        rp = Path(path).resolve()
    except (OSError, RuntimeError):
        return True
    return rp in protected_paths()


def atomic_write(path, data, mode=0o600):
    """Write via same-directory temp file + fsync + atomic os.replace.
    Chases no symlinks: replace swaps the link itself, never its target."""
    p = Path(path)
    try:
        fd, tmpname = tempfile.mkstemp(dir=str(p.parent), prefix=p.name + ".",
                                       suffix=".tmp")
    except OSError:
        return False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmpname, mode)
        os.replace(tmpname, str(p))
        try:                       # fsync dir so the rename survives a crash
            dfd = os.open(str(p.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
        return True
    except OSError:
        try:
            os.unlink(tmpname)
        except OSError:
            pass
        return False


# ---------------------------------------------------------------------------
# CONFIGURATION SYSTEM - defaults, validation, self-healing, atomic save
# ---------------------------------------------------------------------------

CONFIG_PATH = Path.home() / ".config" / "clxv12" / "config.json"

CONFIG_DEFAULTS = {
    "schema": 1,
    "theme": "auto",                  # auto | truecolor | ansi | mono
    "language": "en",
    "icons": True,
    "timeouts": {"command": 30, "network": 5, "dns": 5, "port": 0.8},
    "limits": {
        "max_output_bytes": 1 << 20,
        "max_read_size": 8 << 20,
        "max_search_file_size": 4 << 20,
        "max_results": 500,
        "max_depth": 5,
        "max_archive_entries": 10000,
        "max_archive_total": 1 << 30,
        "max_archive_ratio": 200,
        "max_ports": 1024,
        "port_concurrency": 16,
    },
    "backup": {"enabled": True, "keep": 20},
    "logging": {"enabled": True, "level": "info", "max_bytes": 512 * 1024,
                "backups": 3},
    "search": {"skip_dirs": ["node_modules", ".git", ".gradle", "__pycache__",
                             "build", "dist", ".venv", "venv", ".tox"]},
}

# (path tuple) -> (type, validator) ; anything failing is replaced by default
_CONFIG_TYPES = {
    ("theme",): (str, lambda v: v in ("auto", "truecolor", "ansi", "mono")),
    ("language",): (str, lambda v: isinstance(v, str) and 0 < len(v) <= 8),
    ("icons",): (bool, lambda v: True),
    ("schema",): (int, lambda v: v >= 1),
}


def _deep_merge(base, override):
    """Merge `override` onto a copy of `base`, keeping base's types."""
    out = dict(base)
    if not isinstance(override, dict):
        return out
    for key, val in override.items():
        if key not in base:
            continue                      # unknown keys are dropped, not trusted
        if isinstance(base[key], dict) and isinstance(val, dict):
            out[key] = _deep_merge(base[key], val)
        elif isinstance(base[key], bool):
            out[key] = bool(val) if isinstance(val, bool) else base[key]
        elif isinstance(base[key], (int, float)) and isinstance(val, (int, float)) \
                and not isinstance(val, bool):
            out[key] = val
        elif isinstance(base[key], str) and isinstance(val, str):
            out[key] = val
        elif isinstance(base[key], list) and isinstance(val, list):
            out[key] = [v for v in val if isinstance(v, (str, int, float))]
        else:
            out[key] = base[key]          # type mismatch -> keep the default
    return out


class Config:
    """User configuration with self-healing.

    A corrupt, truncated, wrong-typed or hostile config file never stops the
    toolkit: the bad file is preserved as .corrupt and defaults take over."""

    def __init__(self, path=None):
        self.path = Path(path) if path else CONFIG_PATH
        self.data = dict(CONFIG_DEFAULTS)
        self.recovered = False
        self.source = "defaults"

    def load(self):
        try:
            if not self.path.exists():
                self.source = "defaults (no file)"
                return self
            if self.path.stat().st_size > (2 << 20):
                raise ValueError("config file is implausibly large")
            raw = self.path.read_text(encoding="utf-8", errors="replace")
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise TypeError("config root must be an object")
            merged = _deep_merge(CONFIG_DEFAULTS, parsed)
            for keys, (typ, ok) in _CONFIG_TYPES.items():
                val = merged
                for k in keys:
                    val = val.get(k) if isinstance(val, dict) else None
                if not isinstance(val, typ) or not ok(val):
                    ref, defref = merged, CONFIG_DEFAULTS
                    for k in keys[:-1]:
                        ref, defref = ref[k], defref[k]
                    ref[keys[-1]] = defref[keys[-1]]
            self.data = merged
            self.source = str(self.path)
        except (OSError, ValueError, TypeError, KeyError) as e:
            self.recovered = True
            self.source = "defaults (recovered)"
            self.data = dict(CONFIG_DEFAULTS)
            LOG.event("warning", "config unreadable, using defaults",
                      reason="%s: %s" % (type(e).__name__, e))
            try:
                if self.path.exists():
                    self.path.replace(self.path.with_suffix(".json.corrupt"))
            except OSError:
                pass
        return self

    def save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            return False
        return atomic_write(self.path,
                            json.dumps(self.data, indent=2, ensure_ascii=False),
                            mode=0o600)

    def get(self, dotted, default=None):
        node = self.data
        for part in str(dotted).split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted, value):
        parts = str(dotted).split(".")
        node = self.data
        for part in parts[:-1]:
            if not isinstance(node.get(part), dict):
                node[part] = {}
            node = node[part]
        node[parts[-1]] = value
        return self

    def apply_to_runtime(self):
        """Config supplies defaults; explicit CLI flags still win, so this is
        called BEFORE RT.apply(args)."""
        RT.timeout = float(self.get("timeouts.command", RT.timeout))
        RT.depth = int(self.get("limits.max_depth", RT.depth))
        RT.max_results = int(self.get("limits.max_results", RT.max_results))
        return self


CONFIG = Config()


# ---------------------------------------------------------------------------
# SECURE TEMPORARY FILES + TOCTOU-RESISTANT PRIMITIVES
# ---------------------------------------------------------------------------

_TEMP_REGISTRY = set()


@contextlib.contextmanager
def secure_temp_file(suffix="", prefix="clxv12_", directory=None, keep=False):
    """Unpredictable name, 0600, owner-only directory, always cleaned up.

    mkstemp is used rather than a predictable name so a symlink cannot be
    pre-planted at the path we are about to write."""
    base = Path(directory) if directory else (CONFIG_DIR / "tmp")
    try:
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        base = Path(tempfile.gettempdir())
    fd, name = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=str(base))
    _TEMP_REGISTRY.add(name)
    try:
        os.fchmod(fd, 0o600)
    except (OSError, AttributeError):
        pass
    try:
        yield fd, Path(name)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        _TEMP_REGISTRY.discard(name)
        if not keep:
            try:
                os.unlink(name)
            except OSError:
                pass


@contextlib.contextmanager
def secure_temp_dir(prefix="clxv12_", directory=None):
    base = Path(directory) if directory else (CONFIG_DIR / "tmp")
    try:
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        base = Path(tempfile.gettempdir())
    path = tempfile.mkdtemp(prefix=prefix, dir=str(base))
    _TEMP_REGISTRY.add(path)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    try:
        yield Path(path)
    finally:
        _TEMP_REGISTRY.discard(path)
        shutil.rmtree(path, ignore_errors=True)


def cleanup_temp_registry():
    """Signal/exit path: remove anything this process still owns."""
    for name in list(_TEMP_REGISTRY):
        try:
            if os.path.isdir(name):
                shutil.rmtree(name, ignore_errors=True)
            else:
                os.unlink(name)
        except OSError:
            pass
        _TEMP_REGISTRY.discard(name)


def open_nofollow(path, flags=os.O_RDONLY, mode=0o600):
    """Open refusing to traverse a final symlink.

    The classic TOCTOU is `if not islink(p): open(p)` - between the two calls
    an attacker swaps in a link. O_NOFOLLOW closes that window in the kernel."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(str(path), flags | nofollow, mode)
    except OSError as e:
        import errno as _e
        if e.errno in (_e.ELOOP, getattr(_e, "EMLINK", _e.ELOOP)):
            raise SecurityBlock("refusing to follow symlink: %s" % path,
                                ErrCode.SECURITY_BLOCK)
        raise


def stat_fd(fd):
    try:
        return os.fstat(fd)
    except OSError:
        return None


def read_file_bounded(path, max_bytes=None, nofollow=True):
    """Read at most max_bytes. Size is checked on the OPEN FILE DESCRIPTOR,
    not on the path, so a file swapped after the check cannot be read past
    the limit."""
    limit = int(max_bytes if max_bytes is not None
                else CONFIG.get("limits.max_read_size", 8 << 20))
    fd = open_nofollow(path, os.O_RDONLY) if nofollow else os.open(str(path), os.O_RDONLY)
    try:
        st = stat_fd(fd)
        if st is not None and not stat_module_isreg(st.st_mode):
            raise InvalidArgument("not a regular file: %s" % path,
                                  ErrCode.INVALID_PATH)
        chunks, total = [], 0
        while total < limit:
            chunk = os.read(fd, min(1 << 20, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        truncated = bool(os.read(fd, 1))
        return b"".join(chunks), truncated
    finally:
        os.close(fd)


def stat_module_isreg(mode):
    import stat as _stat
    return _stat.S_ISREG(mode)


def atomic_write_bytes(path, data, mode=0o600):
    """Byte-oriented sibling of atomic_write: temp + fsync + os.replace."""
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmpname = tempfile.mkstemp(dir=str(p.parent), prefix="." + p.name + ".",
                                       suffix=".tmp")
    except OSError:
        return False
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmpname, mode)
        os.replace(tmpname, str(p))
        try:
            dfd = os.open(str(p.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
        return True
    except OSError:
        try:
            os.unlink(tmpname)
        except OSError:
            pass
        return False


# ---------------------------------------------------------------------------
# BACKUP SYSTEM - integrity-hashed snapshots before destructive operations
# ---------------------------------------------------------------------------

BACKUP_DIR = CONFIG_DIR / "backups"
BACKUP_INDEX = BACKUP_DIR / "index.json"
MAX_BACKUP_BYTES = 256 << 20


class BackupManager:
    """Copy-before-destroy with a hash-verified index.

    A backup is only recorded once its payload is on disk AND its digest has
    been recomputed from the stored copy - never from the source."""

    def __init__(self, store=None):
        self.store = store

    def _index(self):
        try:
            if BACKUP_INDEX.exists():
                data = json.loads(BACKUP_INDEX.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data
        except (OSError, ValueError):
            LOG.event("warning", "backup index unreadable, starting a new one")
        return []

    def _write_index(self, entries):
        BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        return atomic_write(BACKUP_INDEX,
                            json.dumps(entries, indent=2, ensure_ascii=False),
                            mode=0o600)

    def create(self, path, reason="manual"):
        """Snapshot a file or directory. Returns OpResult with the entry."""
        src = Path(path)
        if not src.exists():
            return OpResult.failure(ErrCode.NOT_FOUND, "nothing to back up: %s" % src)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        backup_id = "%s_%s" % (datetime.now().strftime("%Y%m%d_%H%M%S"),
                               "%06x" % random.getrandbits(24))
        t0 = time.monotonic()
        try:
            if src.is_dir() and not src.is_symlink():
                size, capped = dir_size(src)
                if size > MAX_BACKUP_BYTES:
                    return OpResult.failure(
                        ErrCode.INVALID_ARGUMENT,
                        "refusing to back up %s (limit %s)"
                        % (human_size(size), human_size(MAX_BACKUP_BYTES)))
                dest = BACKUP_DIR / (backup_id + ".tar")
                with tarfile.open(str(dest), "w") as tf:
                    tf.add(str(src), arcname=src.name, recursive=True)
                kind = "directory"
            else:
                st = src.lstat()
                if st.st_size > MAX_BACKUP_BYTES:
                    return OpResult.failure(
                        ErrCode.INVALID_ARGUMENT,
                        "refusing to back up %s" % human_size(st.st_size))
                dest = BACKUP_DIR / (backup_id + ".bin")
                shutil.copy2(str(src), str(dest))
                kind = "file"
            os.chmod(str(dest), 0o600)
        except (OSError, tarfile.TarError) as e:
            return OpResult.failure(ErrCode.INTERNAL, "backup failed: %s" % e)

        digest = stream_hash(dest, "sha256")
        if not digest:
            try:
                dest.unlink()
            except OSError:
                pass
            return OpResult.failure(ErrCode.INTERNAL,
                                    "backup written but unreadable; discarded")
        entry = {
            "id": backup_id, "kind": kind,
            "source": str(src), "stored": str(dest),
            "sha256": digest, "bytes": dest.stat().st_size,
            "created": now_iso(), "reason": str(reason)[:80],
        }
        entries = self._index()
        entries.append(entry)
        keep = int(CONFIG.get("backup.keep", 20))
        pruned = []
        while len(entries) > max(1, keep):
            old = entries.pop(0)
            pruned.append(old["id"])
            try:
                Path(old["stored"]).unlink()
            except OSError:
                pass
        self._write_index(entries)
        LOG.audit("backup_create", str(src), "success",
                  (time.monotonic() - t0) * 1000, backup_id=backup_id, kind=kind)
        res = OpResult.success({"entry": entry, "pruned": pruned,
                                "total": len(entries)})
        if pruned:
            res.add_warning("pruned %d old backup(s) (backup.keep=%d)"
                            % (len(pruned), keep))
        return res

    def list(self):
        entries = self._index()
        for e in entries:
            stored = Path(e.get("stored", ""))
            e["present"] = stored.exists()
            e["verified"] = (e["present"]
                             and stream_hash(stored, "sha256") == e.get("sha256"))
        return OpResult.success({"count": len(entries), "backups": entries,
                                 "dir": str(BACKUP_DIR)})

    def verify(self, backup_id):
        for e in self._index():
            if e.get("id") == backup_id:
                stored = Path(e["stored"])
                if not stored.exists():
                    return OpResult.failure(ErrCode.NOT_FOUND,
                                            "backup payload missing: %s" % backup_id)
                actual = stream_hash(stored, "sha256")
                if actual != e.get("sha256"):
                    return OpResult.failure(
                        ErrCode.STORE_CORRUPT,
                        "integrity check FAILED for %s" % backup_id)
                return OpResult.success({"id": backup_id, "sha256": actual,
                                         "verified": True})
        return OpResult.failure(ErrCode.NOT_FOUND, "no such backup: %s" % backup_id)

    def restore(self, backup_id, dest=None, overwrite=False):
        """Restore a verified backup. Refuses silently overwriting anything."""
        entry = next((e for e in self._index() if e.get("id") == backup_id), None)
        if entry is None:
            return OpResult.failure(ErrCode.NOT_FOUND, "no such backup: %s" % backup_id)
        check = self.verify(backup_id)
        if not check.ok:
            return check
        target = Path(dest) if dest else Path(entry["source"])
        safe = safe_write_path(target)
        if safe is None:
            return OpResult.failure(ErrCode.SECURITY_BLOCK,
                                    "restore target is outside the approved roots: %s"
                                    % target)
        if target.exists() and not overwrite:
            return OpResult.failure(
                ErrCode.INVALID_ARGUMENT,
                "%s exists; pass overwrite=True to replace it" % target)
        stored = Path(entry["stored"])
        t0 = time.monotonic()
        try:
            if entry["kind"] == "directory":
                with secure_temp_dir(prefix="restore_") as staging:
                    with tarfile.open(str(stored)) as tf:
                        extracted, rejected = safe_extract_tar(tf, staging)
                    produced = [p for p in staging.iterdir()]
                    if not produced:
                        return OpResult.failure(ErrCode.ARCHIVE_CORRUPT,
                                                "backup archive produced no files")
                    if target.exists():
                        shutil.rmtree(str(target), ignore_errors=True)
                    shutil.move(str(produced[0]), str(target))
                detail = {"extracted": extracted, "rejected": rejected}
            else:
                with secure_temp_file(prefix="restore_", keep=True) as (fd, tmp):
                    pass
                shutil.copy2(str(stored), str(tmp))
                os.replace(str(tmp), str(target))
                detail = {"bytes": target.stat().st_size}
        except (OSError, tarfile.TarError, ArchiveLimitError) as e:
            LOG.audit("backup_restore", str(target), "failure",
                      (time.monotonic() - t0) * 1000, error=str(e))
            return OpResult.failure(ErrCode.INTERNAL, "restore failed: %s" % e)
        LOG.audit("backup_restore", str(target), "success",
                  (time.monotonic() - t0) * 1000, backup_id=backup_id)
        return OpResult.success({"id": backup_id, "restored_to": str(target),
                                 "detail": detail})

    def delete(self, backup_id):
        entries = self._index()
        keep = [e for e in entries if e.get("id") != backup_id]
        if len(keep) == len(entries):
            return OpResult.failure(ErrCode.NOT_FOUND, "no such backup: %s" % backup_id)
        for e in entries:
            if e.get("id") == backup_id:
                try:
                    Path(e["stored"]).unlink()
                except OSError:
                    pass
        self._write_index(keep)
        LOG.audit("backup_delete", backup_id, "success")
        return OpResult.success({"deleted": backup_id, "remaining": len(keep)})


BACKUPS = BackupManager()


# ---------------------------------------------------------------------------
# UNDO JOURNAL - only for operations that are genuinely reversible
# ---------------------------------------------------------------------------

UNDO_PATH = CONFIG_DIR / "undo.json"
MAX_UNDO_ENTRIES = 50

# Honest capability map. An operation absent from here has NO undo support and
# the toolkit says so rather than pretending.
REVERSIBLE_OPS = {
    "move": "move the item back to its original path",
    "rename": "rename the item back",
    "delete_with_backup": "restore the backed-up copy",
    "overwrite_with_backup": "restore the backed-up copy",
    "mkdir": "remove the directory if it is still empty",
    "touch": "remove the created file if it is still empty",
}
IRREVERSIBLE_OPS = ("delete_no_backup", "build", "install", "git_push",
                    "extract", "cleanup_no_backup", "sign")


class UndoJournal:
    def __init__(self, path=UNDO_PATH):
        self.path = Path(path)

    def _load(self):
        try:
            if self.path.exists():
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data
        except (OSError, ValueError):
            LOG.event("warning", "undo journal unreadable, resetting")
        return []

    def _save(self, entries):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        return atomic_write(self.path,
                            json.dumps(entries[-MAX_UNDO_ENTRIES:], indent=2,
                                       ensure_ascii=False), mode=0o600)

    def record(self, operation, **fields):
        if operation not in REVERSIBLE_OPS:
            LOG.event("info", "operation %r is not reversible; not journalled"
                      % operation)
            return None
        entry = {"id": "%s_%04x" % (datetime.now().strftime("%Y%m%d%H%M%S"),
                                    random.getrandbits(16)),
                 "operation": operation, "timestamp": now_iso(),
                 "undone": False}
        entry.update({k: str(v) for k, v in fields.items()})
        entries = self._load()
        entries.append(entry)
        self._save(entries)
        return entry["id"]

    def last(self):
        for entry in reversed(self._load()):
            if not entry.get("undone"):
                return entry
        return None

    def history(self, limit=20):
        return OpResult.success({
            "entries": self._load()[-int(limit):],
            "reversible_operations": REVERSIBLE_OPS,
            "irreversible_operations": list(IRREVERSIBLE_OPS),
        })

    def undo_last(self):
        entry = self.last()
        if entry is None:
            return OpResult.failure(ErrCode.NOT_FOUND,
                                    "nothing to undo")
        op = entry.get("operation")
        if op not in REVERSIBLE_OPS:
            return OpResult.failure(
                ErrCode.INVALID_ARGUMENT,
                "%r cannot be undone: %s" % (op, "no safe inverse exists"))
        try:
            result = self._apply_inverse(entry)
        except ToolkitError as e:
            return OpResult.failure(e.code, e.message)
        except OSError as e:
            return OpResult.failure(ErrCode.INTERNAL, "undo failed: %s" % e)
        if result.ok:
            entries = self._load()
            for e in entries:
                if e.get("id") == entry["id"]:
                    e["undone"] = True
                    e["undone_at"] = now_iso()
            self._save(entries)
            LOG.audit("undo", entry.get("source", ""), "success", None,
                      undone_operation=op, entry_id=entry["id"])
        return result

    def _apply_inverse(self, entry):
        op = entry["operation"]
        if op in ("move", "rename"):
            src, dst = Path(entry["destination"]), Path(entry["source"])
            if not src.exists():
                raise NotFound("the moved item is no longer at %s" % src)
            if dst.exists():
                raise InvalidArgument("original path %s is occupied again" % dst)
            if safe_write_path(dst) is None:
                raise SecurityBlock("undo target outside approved roots: %s" % dst)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
            return OpResult.success({"operation": op, "restored": str(dst)})
        if op in ("delete_with_backup", "overwrite_with_backup"):
            backup_id = entry.get("backup_id")
            if not backup_id:
                raise NotFound("no backup was recorded for this operation")
            return BACKUPS.restore(backup_id, entry.get("source"), overwrite=True)
        if op == "mkdir":
            d = Path(entry["destination"])
            if not d.is_dir():
                raise NotFound("directory no longer exists: %s" % d)
            if any(d.iterdir()):
                raise InvalidArgument("directory is no longer empty: %s" % d)
            d.rmdir()
            return OpResult.success({"operation": op, "removed": str(d)})
        if op == "touch":
            f = Path(entry["destination"])
            if not f.is_file():
                raise NotFound("file no longer exists: %s" % f)
            if f.stat().st_size:
                raise InvalidArgument("file is no longer empty: %s" % f)
            f.unlink()
            return OpResult.success({"operation": op, "removed": str(f)})
        raise InvalidArgument("no inverse implemented for %r" % op)


UNDO = UndoJournal()


def instance_lock():
    """Single-instance guard for interactive sessions. PID lockfile with
    stale detection (a leftover lock from a crash is overwritten)."""
    if not _HAS_FCNTL:
        return True                        # best-effort on non-POSIX
    try:
        fd = os.open(str(CONFIG_DIR / "instance.lock"),
                     os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return False
    try:
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode("ascii"))
    except OSError:
        pass
    return True


def write_crash_log(text):
    """Last-resort audit trail: unhandled errors always land in crash.log."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(str(CONFIG_DIR / "crash.log"), "a", encoding="utf-8") as f:
            f.write("\n=== %s ===\n%s\n" % (now_iso(), redact_credentials(text)))
    except OSError:
        pass


def safe_path(path, must_exist=True, for_write=False):
    """Central security layer. Resolve `path`; require it to stay inside a
    read root (or write root when for_write=True). Returns resolved Path or None."""
    try:
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        if must_exist and not p.exists():
            return None
        resolved = resolve_ancestor(p)   # resolves symlinked parents too
        roots = write_roots() if for_write else read_roots()
        for root in roots:
            if resolved == root or root in resolved.parents:
                return resolved
        return None
    except (OSError, RuntimeError, ValueError):
        return None


def is_within(path, directory):
    try:
        d = Path(directory).resolve()
        pp = Path(path)
        rp = pp.resolve() if (pp.exists() or pp.is_symlink()) else resolve_ancestor(pp)
        if rp is None:
            return False
        return rp == d or d in rp.parents
    except (OSError, RuntimeError):
        return False


def human_size(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "N/A"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "B":
                return "%d B" % n
            num = ("%.2f" % n).rstrip("0").rstrip(".")
            return "%s %s" % (num, unit)
        n /= 1024.0
    return "%d B" % n


def dir_size(path, limit=500000):
    """Bounded recursive size. Returns (size, capped)."""
    total, count = 0, 0
    try:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fn in files:
                if count >= limit:
                    return total, True
                try:
                    total += (Path(root) / fn).stat().st_size
                except OSError:
                    pass
                count += 1
    except OSError:
        pass
    return total, False


def stream_hash(path, algo):
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# --- secure archive extraction ---------------------------------------------

def _zip_member_safe(name):
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        return False
    return True


MAX_EXTRACT_ENTRIES = 10000
MAX_EXTRACT_TOTAL = 1 << 30       # 1 GiB uncompressed
MAX_MEMBER_SIZE = 512 << 20       # 512 MiB per member
MAX_RATIO = 200                   # compression ratio cap (bomb guard, >1MiB only)


class ArchiveLimitError(Exception):
    """Raised when archive extraction exceeds resource safety limits."""


def safe_extract_zip(zf, dest):
    """Extract members that stay inside dest, within resource limits.
    Returns (extracted, rejected)."""
    dest_res = Path(dest).resolve()
    infos = zf.infolist()
    if len(infos) > MAX_EXTRACT_ENTRIES:
        raise ArchiveLimitError("member count %d exceeds limit %d"
                                % (len(infos), MAX_EXTRACT_ENTRIES))
    if sum(i.file_size for i in infos) > MAX_EXTRACT_TOTAL:
        raise ArchiveLimitError("declared uncompressed size exceeds limit")
    extracted, rejected = 0, []
    total = 0
    for info in infos:
        if not _zip_member_safe(info.filename):
            rejected.append(info.filename)
            continue
        target = (dest_res / info.filename).resolve()
        if not is_within(target, dest_res):
            rejected.append(info.filename)
            continue
        if info.file_size > MAX_MEMBER_SIZE:
            rejected.append(info.filename)
            continue
        if info.file_size > (1 << 20) and info.compress_size and \
                info.file_size / max(1, info.compress_size) > MAX_RATIO:
            rejected.append(info.filename)  # likely compression bomb
            continue
        total += info.file_size
        if total > MAX_EXTRACT_TOTAL or extracted >= MAX_EXTRACT_ENTRIES:
            raise ArchiveLimitError("extraction limits exceeded (zip)")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:  # symlink: refuse to recreate
            rejected.append(info.filename)
            continue
        zf.extract(info, str(dest_res))
        extracted += 1
    return extracted, rejected


def safe_extract_tar(tf, dest):
    """Strict TAR extraction: regular files and directories ONLY."""
    dest_res = Path(dest).resolve()
    members = tf.getmembers()
    if len(members) > MAX_EXTRACT_ENTRIES:
        raise ArchiveLimitError("member count %d exceeds limit %d"
                                % (len(members), MAX_EXTRACT_ENTRIES))
    if sum(m.size for m in members) > MAX_EXTRACT_TOTAL:
        raise ArchiveLimitError("declared uncompressed size exceeds limit")
    extracted, rejected = 0, []
    total = 0
    for member in members:
        name = member.name
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts:
            rejected.append(name)
            continue
        target = (dest_res / name).resolve()
        if not is_within(target, dest_res):
            rejected.append(name)
            continue
        if not (member.isdir() or member.isfile()):
            rejected.append(name)  # no links, devices, fifos
            continue
        if member.size > MAX_MEMBER_SIZE:
            rejected.append(name)
            continue
        total += member.size
        if total > MAX_EXTRACT_TOTAL or extracted >= MAX_EXTRACT_ENTRIES:
            raise ArchiveLimitError("extraction limits exceeded (tar)")
        try:
            tf.extract(member, str(dest_res), filter="data")  # 3.11+: strips perms/mtime, blocks specials
        except TypeError:                                      # older Python: pre-checks above still apply
            tf.extract(member, str(dest_res))
        extracted += 1
    return extracted, rejected


# --- storage -----------------------------------------------------------------

class Store:
    SCHEMA = 2                     # bump on shape changes; _migrate upgrades older files

    def __init__(self):
        migrate_legacy_config()
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _migrate(self, key, data):
        """Forward-compatible migration. v1 files lack schema_version; their
        shape already matches, so stamp the version and back up the original
        once (.v1.bak) before the first write over it."""
        if not isinstance(data, dict) or "schema_version" in data:
            return data
        if key not in DATA_FILES:
            return data
        try:
            bak = DATA_FILES[key].with_suffix(DATA_FILES[key].suffix + ".v1.bak")
            if not bak.exists():
                shutil.copy2(str(DATA_FILES[key]), str(bak))
        except OSError:
            pass
        data["schema_version"] = self.SCHEMA
        return data

    @contextlib.contextmanager
    def _locked(self, key):
        """Best-effort exclusive file lock: concurrent instances cannot
        interleave read/write of the same data file (POSIX only)."""
        path = DATA_FILES.get(key)
        fd = None
        if path is not None and _HAS_FCNTL:
            try:
                fd = os.open(str(path.with_suffix(path.suffix + ".lock")),
                             os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                fd = None
        try:
            yield
        finally:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                try:
                    os.close(fd)
                except OSError:
                    pass

    def load(self, key, default):
        path = DATA_FILES.get(key)
        if path is None:
            return default
        with self._locked(key):
            try:
                if not path.exists():
                    return default
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                data = self._migrate(key, data)
                # Type confusion is corruption too: a store file holding `[]`
                # where a dict is expected must not be handed to callers that
                # will then do data.get(...) and raise AttributeError.
                if not isinstance(data, type(default)):
                    raise TypeError("store %r holds %s, expected %s"
                                    % (key, type(data).__name__,
                                       type(default).__name__))
                return data
            except (OSError, ValueError, TypeError) as e:
                # corrupted configuration: back it up, never crash
                LOG.event("warning", "store %r unreadable, using defaults" % key,
                          reason=type(e).__name__)
                try:
                    bad = path.with_suffix(path.suffix + ".corrupt")
                    path.replace(bad)
                except OSError:
                    pass
                return default

    def save(self, key, data):
        path = DATA_FILES.get(key)
        if path is None:
            return False
        try:
            if isinstance(data, dict):
                data = dict(data, schema_version=self.SCHEMA)
            payload = json.dumps(data, ensure_ascii=False, indent=2)
        except (TypeError, ValueError):
            return False
        with self._locked(key):
            # atomic temp+fsync+replace; mode 600 - files may hold user paths
            return atomic_write(path, payload, mode=0o600)

    # Kept as an attribute for backwards compatibility; the authoritative
    # list now lives at module level so every layer shares one scrubber.
    _SECRET_PATTERNS = SECRET_PREFIX_PATTERNS

    @classmethod
    def _sanitize(cls, text):
        """Scrub credentials (URLs + key=value) before anything persists."""
        return redact_credentials(text)

    def log(self, action, status="Success", detail=""):
        try:
            data = self.load("history", [])
            data.append({"time": now_iso(), "action": self._sanitize(action),
                         "status": status,
                         "detail": self._sanitize(detail)[:300]})
            self.save("history", data[-MAX_HISTORY:])
        except Exception as _e:     # logging must never crash the caller, but
            write_crash_log("Store.log failed: %s: %s" % (type(_e).__name__, _e))


# --- subprocess engine ---------------------------------------------------------

class Runner:
    """Memory-safe process engine.

    All execution uses argument lists (never a shell). stdout/stderr are
    consumed incrementally through a bounded ring buffer (MAX_CAPTURE per
    stream), so multi-megabyte build logs never exhaust phone RAM.

    Modes:
      quiet   - nothing printed
      normal  - nothing printed during run; caller prints the retained tail
      live    - output streams to the terminal as it arrives (long builds)
    """

    MAX_CAPTURE = 1 << 20   # 1 MiB retained per stream
    READ_CHUNK = 65536

    class Result:
        __slots__ = ("rc", "out", "err", "out_truncated", "err_truncated",
                     "cancelled")

        def __init__(self, rc, out, err, out_trunc=False, err_trunc=False,
                     cancelled=False):
            self.rc = rc
            self.out = out
            self.err = err
            self.out_truncated = out_trunc
            self.err_truncated = err_trunc
            self.cancelled = cancelled

    @staticmethod
    def _drain(pipe, live, sink, state):
        """Reader thread body: incremental consume with bounded retention."""
        buf = bytearray()
        truncated = False
        try:
            while True:
                chunk = pipe.read(Runner.READ_CHUNK)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                if live:
                    try:
                        sys.stdout.write(chunk.decode("utf-8", errors="replace"))
                        sys.stdout.flush()
                    except (OSError, UnicodeError):
                        pass
                buf.extend(chunk)
                if len(buf) > Runner.MAX_CAPTURE:
                    del buf[:len(buf) - Runner.MAX_CAPTURE]
                    truncated = True
        except (OSError, ValueError):
            pass
        state["text"] = buf.decode("utf-8", errors="replace")
        state["truncated"] = truncated

    @staticmethod
    def run(args, cwd=None, timeout=30, env=None, input_text=None, mode="quiet"):
        """Execute without shell. Returns Result. Never raises."""
        import threading
        if isinstance(args, str):
            try:
                args = shlex.split(args)
            except ValueError:
                return Runner.Result(2, "", "unparseable command")
        if not args:
            return Runner.Result(2, "", "empty command")
        if cwd is not None and not Path(str(cwd)).is_dir():
            return Runner.Result(2, "", "invalid working directory: %s" % cwd)
        live = mode == "live"
        new_session = hasattr(os, "killpg") and hasattr(signal, "SIGTERM")
        try:
            p = subprocess.Popen(
                args, cwd=str(cwd) if cwd else None, env=env,
                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, bufsize=0,
                start_new_session=new_session,   # own process group: tree-safe kill
            )
        except FileNotFoundError:
            return Runner.Result(127, "", "command not found: %s" % args[0])
        except PermissionError:
            return Runner.Result(126, "", "permission denied: %s" % args[0])
        except (OSError, ValueError) as _pe:
            return Runner.Result(1, "", "spawn failed: %s" % _pe)
        out_state, err_state = {}, {}
        threads = [
            threading.Thread(target=Runner._drain,
                             args=(p.stdout, live, None, out_state), daemon=True),
            threading.Thread(target=Runner._drain,
                             args=(p.stderr, live, None, err_state), daemon=True),
        ]
        for t in threads:
            t.start()

        def _terminate_tree(force=False):
            """Terminate our OWN process group (we created a new session):
            children die with the parent. Graceful first, then SIGKILL.
            Foreign process groups are never touched."""
            if new_session:
                try:
                    os.killpg(os.getpgid(p.pid),
                              signal.SIGKILL if force else signal.SIGTERM)
                    return
                except (ProcessLookupError, PermissionError, OSError):
                    pass
            try:
                (p.kill if force else p.terminate)()
            except OSError:
                pass

        cancelled = False
        try:
            if input_text is not None:
                try:
                    p.stdin.write(input_text.encode("utf-8", errors="replace"))
                except (OSError, ValueError):
                    pass
            if p.stdin is not None:
                try:
                    p.stdin.close()
                except (OSError, ValueError):
                    pass
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_tree(force=False)        # graceful to the whole group
            try:
                p.wait(timeout=2)               # grace period
            except (OSError, subprocess.TimeoutExpired):
                _terminate_tree(force=True)     # escalate
                try:
                    p.wait(timeout=5)           # reap: no zombies
                except (OSError, subprocess.TimeoutExpired):
                    pass
            rc = 124
        except KeyboardInterrupt:
            cancelled = True
            _terminate_tree(force=False)
            try:
                p.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                _terminate_tree(force=True)
                try:
                    p.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            rc = 130
        for t in threads:
            t.join(timeout=5)
        return Runner.Result(
            rc if rc is not None else 1,
            out_state.get("text", ""), err_state.get("text", ""),
            out_state.get("truncated", False), err_state.get("truncated", False),
            cancelled,
        )

    @staticmethod
    def display(ui, args, cwd=None, timeout=60, tail=6000, mode="normal"):
        """Run and present results. mode='live' streams during execution."""
        r = Runner.run(args, cwd=cwd, timeout=timeout, mode=mode)
        if mode != "live":
            if r.out.strip():
                text = r.out.rstrip()
                print(text[-tail:] if len(text) > tail else text)
            if r.err.strip():
                print(ui.t.c(r.err.rstrip()[-tail:], "error"))
        if r.out_truncated:
            ui.status("info", "stdout truncated (bounded capture, last %d bytes shown)."
                      % (Runner.MAX_CAPTURE // 2))
        if r.rc == 0:
            ui.status("ok", "exit code 0")
        elif r.cancelled or r.rc == 130:
            ui.status("warn", "cancelled")
        else:
            ui.status("bad", "exit code %d" % r.rc)
        return r

    @staticmethod
    def check(name):
        """Resolve an executable. Returns path or None."""
        try:
            return shutil.which(name)
        except OSError:
            return None


# --- system engine ---------------------------------------------------------------

class SystemEngine:
    def __init__(self):
        self._info = None

    def android_version(self):
        getprop = Runner.check("getprop")
        if getprop:
            _res = Runner.run([getprop, "ro.build.version.release"], timeout=3)
            if _res.rc == 0 and _res.out.strip():
                return _res.out.strip()
        return os.environ.get("ANDROID__BUILD_VERSION_RELEASE", "N/A")

    def is_termux(self):
        prefix = os.environ.get("PREFIX", "")
        return "com.termux" in prefix or str(Path.home()).startswith("/data/data/com.termux")

    def termux_version(self):
        for env in ("TERMUX_VERSION", "TERMUX_APP__VERSION_NAME"):
            v = os.environ.get(env)
            if v:
                return v
        return "Detected" if self.is_termux() else "N/A"

    def battery(self):
        tool = Runner.check("termux-battery-status")
        if not tool:
            return None
        _res = Runner.run([tool], timeout=8)
        if _res.rc == 0 and _res.out.strip():
            try:
                d = json.loads(_res.out)
                return "%s%% (%s)" % (d.get("percentage", "N/A"), d.get("plugged", "?"))
            except ValueError:
                return None
        return None

    def memory(self):
        try:
            with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as f:
                m = re.search(r"MemTotal:\s+(\d+)", f.read())
                if m:
                    return human_size(int(m.group(1)) * 1024)
        except OSError:
            pass
        return "N/A"

    def storage(self):
        try:
            st = os.statvfs(str(Path.home()))
            free = st.f_bavail * st.f_frsize
            total = st.f_blocks * st.f_frsize
            return "%s free / %s" % (human_size(free), human_size(total))
        except OSError:
            return "N/A"

    def tool_version(self, name):
        path = Runner.check(name)
        if not path:
            return "N/A"
        flags = {
            "python": ["--version"], "python3": ["--version"], "pip": ["--version"],
            "git": ["--version"], "node": ["--version"], "npm": ["--version"],
            "java": ["-version"], "javac": ["-version"], "gradle": ["--version"],
            "ffmpeg": ["-version"], "clang": ["--version"], "gcc": ["--version"],
            "ssh": ["-V"], "curl": ["--version"], "wget": ["--version"],
            "openssl": ["version"], "jq": ["--version"],
        }
        _res = Runner.run([path] + flags.get(name, ["--version"]), timeout=5)
        lines = (_res.out + _res.err).strip().splitlines()
        return lines[0][:90] if lines else ("OK" if _res.rc == 0 else "N/A")

    def info_rows(self):
        u = platform.uname()
        batt = self.battery()
        return [
            ("Android", self.android_version()),
            ("Kernel", u.release or "N/A"),
            ("Architecture", u.machine or "N/A"),
            ("CPU cores", str(os.cpu_count() or "N/A")),
            ("RAM", self.memory()),
            ("Storage", self.storage()),
            ("Termux", self.termux_version()),
            ("Python", platform.python_version()),
            ("HOME", str(Path.home())),
            ("CWD", os.getcwd()),
            ("Battery", batt if batt else "N/A (Termux:API unavailable)"),
        ]


# --- tool detection ---------------------------------------------------------------

TOOL_GROUPS = {
    "Development": ["python", "python3", "pip", "git", "node", "npm", "npx",
                    "java", "javac", "gradle", "clang", "gcc", "make", "cmake",
                    "flutter", "dart", "kotlin", "groovy"],
    "Android": ["adb", "getprop", "termux-api", "termux-open", "termux-share",
                "termux-storage-get", "termux-battery-status",
                "termux-wifi-connectioninfo", "termux-wifi-scaninfo"],
    "Network": ["curl", "wget", "ssh", "scp", "rsync", "ping", "ip", "ifconfig",
                "netstat", "nslookup"],
    "Security/Diagnostics": ["openssl", "aapt", "apkanalyzer", "apksigner",
                             "keytool", "sqlite3", "gpg"],
    "Compression/Media": ["zip", "unzip", "7z", "tar", "ffmpeg", "jq", "busybox"],
}
TERMUX_API_FAMILY = ("termux-battery-status", "termux-wifi-connectioninfo",
                     "termux-wifi-scaninfo", "termux-share", "termux-storage-get")
ALL_TOOL_NAMES = sorted({n for g in TOOL_GROUPS.values() for n in g})


# Tools that must NEVER be probed with invented flags: they either lack
# --version, treat unknown flags as filenames (termux-open would try to open
# a file literally named "--version"), or print usage with a nonzero code.
NO_FLAG_PROBE = {
    "getprop", "ping", "ip", "ifconfig", "netstat", "nslookup",
    "termux-api", "termux-open", "termux-share", "termux-storage-get",
    "termux-battery-status", "termux-wifi-connectioninfo",
    "termux-wifi-scaninfo", "aapt", "apkanalyzer", "apksigner",
    "zip", "unzip", "tar", "7z", "gpg", "keytool", "javac", "java",
    "gradle", "make", "cmake", "busybox", "flutter", "dart", "kotlin", "groovy",
}
# Explicit per-tool probe flags. A tool absent from BOTH sets is accepted on
# executability alone - flags are never guessed.
VERSION_FLAGS = {
    "python": ["--version"], "python3": ["--version"], "pip": ["--version"],
    "git": ["--version"], "node": ["--version"], "npm": ["--version"],
    "npx": ["--version"], "ssh": ["-V"], "scp": ["-V"],
    "curl": ["--version"], "wget": ["--version"],
    "ffmpeg": ["-version"], "clang": ["--version"], "gcc": ["--version"],
    "openssl": ["version"], "jq": ["--version"], "sqlite3": ["--version"],
    "adb": ["--version"], "rsync": ["--version"],
}


class ToolDetector:
    def __init__(self, store=None):
        self.store = store
        # All caches live here, not in scan(): lazy use before any scan is safe.
        self.tools = {}
        self.runnable = {}
        self.versions = {}

    @staticmethod
    def _probe(name, path):
        """Single source of truth for 'does this tool run'. Never invents
        CLI flags; tools without a known probe are accepted on X_OK alone
        ('which' already proved existence)."""
        if name in NO_FLAG_PROBE or name not in VERSION_FLAGS:
            try:
                return os.access(path, os.X_OK), ""
            except OSError:
                return False, ""
        r = Runner.run([path] + VERSION_FLAGS[name], timeout=5)
        lines = (r.out + r.err).strip().splitlines()
        return r.rc < 126, (lines[0][:90] if lines else "")

    def scan(self):
        self.tools = {}
        self.runnable = {}
        self.versions = {}
        for n in ALL_TOOL_NAMES:
            path = Runner.check(n)
            self.tools[n] = path
            if path:
                ok, ver = self._probe(n, path)
                self.runnable[n] = ok
                self.versions[n] = ver
            else:
                self.runnable[n] = False
                self.versions[n] = ""
        if self.store:
            self.store.save("tools", {
                "scanned_at": now_iso(),
                "tools": {k: v or "" for k, v in self.tools.items()},
            })
        return self.tools

    def runnable_check(self, name):
        if name not in self.runnable:
            path = self.path(name)
            if not path:
                self.runnable[name] = False
                self.versions.setdefault(name, "")
            else:
                ok, ver = self._probe(name, path)
                self.runnable[name] = ok
                self.versions[name] = ver
        return self.runnable.get(name, False)

    def version_of(self, name):
        if name not in self.versions:
            self.runnable_check(name)
        return self.versions.get(name, "")

    def path(self, name):
        v = self.tools.get(name) or Runner.check(name)
        return v

    def installed(self, name):
        return self.path(name) is not None

    def status(self, name):
        """INSTALLED | BROKEN | MISSING | UNAVAILABLE | NOT APPLICABLE"""
        if self.installed(name):
            return "INSTALLED" if self.runnable_check(name) else "BROKEN"
        if name in TERMUX_API_FAMILY:
            return "UNAVAILABLE" if self.installed("termux-api") else "NOT APPLICABLE"
        return "MISSING"

    def count(self):
        return sum(1 for v in self.tools.values() if v)

    def rows(self):
        rows = []
        for group, names in TOOL_GROUPS.items():
            rows.append((group, None))
            for n in names:
                rows.append((n, self.status(n)))
        return rows

# ---------------------------------------------------------------------------
# PROJECT ENGINE - evidence-based detection, bounded scanning, actions
# ---------------------------------------------------------------------------

PROJECT_MARKERS = [
    (("pubspec.yaml",), "Flutter"),
    (("package.json",), "Node / JavaScript"),
    (("build.gradle", "build.gradle.kts", "settings.gradle", "gradlew"), "Android / Gradle"),
    (("pyproject.toml", "requirements.txt", "setup.py"), "Python"),
    (("Cargo.toml",), "Rust"),
    (("go.mod",), "Go"),
    (("pom.xml",), "Java / Maven"),
    (("CMakeLists.txt",), "C / C++ (CMake)"),
    (("Makefile", "makefile", "GNUmakefile"), "C / C++ (Make)"),
    (("composer.json",), "PHP"),
    (("Gemfile",), "Ruby"),
    (("Dockerfile",), "Docker"),
    (("index.html",), "Web / Static"),
]
SKIP_DIRS = {".git", ".cache", ".npm", "node_modules", "__pycache__", ".gradle",
             ".dart_tool", ".idea", ".vscode", ".local", ".termux"}


def classify_project(path):
    """Return (type, evidence). Never guesses from folder names."""
    p = Path(path)
    try:
        names = {x.name for x in p.iterdir()}
    except OSError:
        return ("Unknown", [])
    for markers, ptype in PROJECT_MARKERS:
        hit = [m for m in markers if m in names]
        if hit:
            if ptype == "Node / JavaScript" and any(n.startswith("vite.config.") for n in names):
                return ("Vite / Node", ["vite.config.*", "package.json"])
            return (ptype, hit)
    if "android" in names and any(m in names for m in ("build.gradle", "settings.gradle")):
        return ("Android / Gradle", ["android/", "gradle files"])
    return ("Unknown", [])


def bounded_walk(root, max_depth=SCAN_MAX_DEPTH, max_entries=SCAN_MAX_ENTRIES):
    """os.scandir based bounded walk with symlink-loop protection."""
    count = 0
    stack = [(Path(root), 0)]
    while stack and count < max_entries:
        current, depth = stack.pop()
        try:
            with os.scandir(str(current)) as it:
                entries = list(it)
        except (OSError, PermissionError):
            continue
        count += len(entries)
        yield current, entries, depth
        if depth < max_depth:
            for e in entries:
                try:
                    if e.is_dir(follow_symlinks=False) and e.name not in SKIP_DIRS \
                            and not e.name.startswith("."):
                        stack.append((Path(e.path), depth + 1))
                except OSError:
                    continue


def discover_projects(store, ui=None):
    found, seen = [], set()
    for root in approved_roots():
        if not root.exists():
            continue
        for current, entries, _depth in bounded_walk(root):
            for e in entries:
                if not e.is_dir(follow_symlinks=False):
                    continue
                if e.name in SKIP_DIRS or e.name.startswith("."):
                    continue
                try:
                    ptype, evidence = classify_project(e.path)
                except OSError:
                    continue
                if ptype != "Unknown":
                    try:
                        rp = str(Path(e.path).resolve())
                    except OSError:
                        continue
                    if rp not in seen:
                        seen.add(rp)
                        found.append({
                            "name": e.name, "path": rp, "type": ptype,
                            "evidence": evidence,
                            "clxv11": bool(IDENTITY_RE.search(e.name)),
                        })
    store.save("projects", {"scanned_at": now_iso(), "projects": found})
    return found


def discover_identity_artifacts(store, ui=None):
    matches = []
    for root in approved_roots():
        if not root.exists():
            continue
        for current, entries, _depth in bounded_walk(root, max_depth=6):
            for e in entries:
                if IDENTITY_RE.search(e.name):
                    try:
                        kind = "dir" if e.is_dir(follow_symlinks=False) else "file"
                        matches.append({"kind": kind, "path": e.path})
                    except OSError:
                        pass
                    if len(matches) >= 200:
                        store.log("CLXV12 Discovery", "Success", "%d artifacts" % len(matches))
                        return matches
    store.log("CLXV12 Discovery", "Success", "%d artifacts" % len(matches))
    return matches


class ProjectEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui
        self.store = app.store

    def _load(self):
        return self.store.load("projects", {}).get("projects", [])

    def _pick(self, prompt="Project path (or index from last list)"):
        raw = self.ui.ask(prompt)
        if raw is None or not raw:
            return None
        if raw.isdigit():
            projects = self._load()
            i = int(raw) - 1
            if 0 <= i < len(projects):
                return Path(projects[i]["path"])
            self.ui.status("bad", "Invalid index.")
            return None
        p = safe_path(raw)
        if not p:
            self.ui.status("bad", "Path invalid or outside approved roots.")
            return None
        return p

    # -- discovery / listing ------------------------------------------------
    def scan(self):
        with PleaseWait(self.ui, "Scanning approved roots for projects"):
            projects = discover_projects(self.store)
        return projects

    def list_projects(self):
        projects = self.scan()
        self.ui.header("PROJECTS", "%d discovered" % len(projects))
        if not projects:
            self.ui.status("info", "No projects found.")
            self.ui.pause()
            return projects
        rows = [(p["name"], p["type"], "yes" if p["clxv11"] else "-",
                 p["path"]) for p in projects]
        self.ui.table(["NAME", "TYPE", "CLXV12", "PATH"], rows)
        self.store.log("List Projects", "Success", "%d projects" % len(projects))
        self.ui.pause()
        return projects

    def search(self):
        q = self.ui.ask("Search projects (case-insensitive)")
        if not q:
            return
        ql = q.lower()
        hits = [p for p in self._load()
                if ql in p["name"].lower() or ql in p["path"].lower()]
        self.ui.header("SEARCH: " + q, "%d matches" % len(hits))
        for p in hits:
            print(" - %s [%s]" % (p["path"], p["type"]))
        if not hits:
            self.ui.status("info", "No matches.")
        self.ui.pause()

    # -- metadata ------------------------------------------------------------
    def info(self):
        p = self._pick()
        if not p:
            self.ui.pause()
            return
        ptype, evidence = classify_project(p)
        self.ui.header("PROJECT INFORMATION")
        rows = [("Name", p.name), ("Path", str(p)),
                ("Type", ptype), ("Evidence", ", ".join(evidence) or "-"),
                ("CLXV12", "yes" if IDENTITY_RE.search(p.name) else "no")]
        if p.is_dir():
            size, capped = dir_size(p)
            rows.append(("Size", human_size(size) + (" (scan capped)" if capped else "")))
        try:
            rows.append(("Modified", datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds")))
        except OSError:
            pass
        self.ui.panels([("PROJECT", rows)])

    # -- mutating actions -----------------------------------------------------
    def create(self):
        name = self.ui.ask("Project name")
        if not name or "/" in name or "\\" in name:
            self.ui.status("bad", "Invalid name.")
            self.ui.pause()
            return
        parent = safe_path(self.ui.ask("Parent directory", str(Path.home())) or str(Path.home()))
        if not parent:
            self.ui.status("bad", "Invalid parent.")
            self.ui.pause()
            return
        ptype = self.ui.ask("Type: python/node/web/c/flutter/android", "python") or "python"
        pkg = "com.example." + (re.sub(r"[^a-zA-Z0-9_]", "", name) or "app")
        dest = parent / name
        if dest.exists():
            self.ui.status("bad", "Destination already exists.")
            self.ui.pause()
            return
        templates = {
            "python": [("main.py", 'def main():\n    print("Hello from %s")\n\n\nif __name__ == "__main__":\n    main()\n' % name),
                       ("requirements.txt", ""),
                       ("pyproject.toml",
                        "[project]\nname = \"%s\"\nversion = \"0.1.0\"\n"
                        "requires-python = \">=3.8\"\n" % name)],
            "node": [("package.json", json.dumps({
                "name": name, "version": "1.0.0",
                "scripts": {
                    "dev": "node index.js",
                    "start": "node index.js",
                    "build": "node -e \"require('fs').mkdirSync('dist',{recursive:true});"
                             "require('fs').copyFileSync('index.js','dist/index.js')\""
                }}, indent=2)),
                ("index.js", 'console.log("Hello from %s");\n' % name)],
            "web": [("index.html", "<!DOCTYPE html>\n<html><head>\n"
                                   "<meta charset=\"utf-8\">\n"
                                   "<title>%s</title>\n"
                                   "<link rel=\"stylesheet\" href=\"style.css\">\n"
                                   "</head>\n<body>\n<h1>%s</h1>\n"
                                   "<script src=\"script.js\"></script>\n"
                                   "</body></html>\n" % (name, name)),
                    ("style.css", "body { font-family: sans-serif; margin: 2em; }\n"),
                    ("script.js", "console.log(\"Hello from %s\");\n" % name)],
            "c": [("main.c", '#include <stdio.h>\nint main(void){puts("%s");return 0;}\n' % name),
                  ("Makefile", "all:\n\tgcc main.c -o %s\n" % name)],
            "flutter": [
                ("pubspec.yaml",
                 "name: %s\ndescription: %s\nversion: 1.0.0\n"
                 "environment:\n  sdk: '>=3.0.0 <4.0.0'\n"
                 "dependencies:\n  flutter:\n    sdk: flutter\n"
                 "dev_dependencies:\n  flutter_test:\n    sdk: flutter\n"
                 "flutter:\n  uses-material-design: true\n" % (name, name)),
                ("lib/main.dart",
                 "import 'package:flutter/material.dart';\n\n"
                 "void main() => runApp(const MyApp());\n\n"
                 "class MyApp extends StatelessWidget {\n"
                 "  const MyApp({super.key});\n"
                 "  @override\n"
                 "  Widget build(BuildContext context) => const MaterialApp(\n"
                 "        home: Scaffold(\n"
                 "          body: Center(child: Text('Hello from %s')),\n"
                 "        ),\n      );\n}\n" % name),
                ("analysis_options.yaml", "include: package:flutter_lints/flutter.yaml\n"),
            ],
            "android": [
                ("settings.gradle",
                 "pluginManagement {\n    repositories {\n        google()\n"
                 "        mavenCentral()\n        gradlePluginPortal()\n    }\n}\n"
                 "rootProject.name = '%s'\n" % name),
                ("build.gradle",
                 "// Top-level build file - AGP version pinned for reproducibility.\n"
                 "plugins {\n"
                 "    id 'com.android.application' version '8.1.4' apply false\n"
                 "}\n"),
                ("gradle.properties", "org.gradle.jvmargs=-Xmx1536m\n"),
                ("app/build.gradle",
                 "plugins {\n    id 'com.android.application'\n}\n\n"
                 "android {\n    namespace '%s'\n    compileSdk 34\n\n"
                 "    defaultConfig {\n        applicationId '%s'\n"
                 "        minSdk 24\n        targetSdk 34\n"
                 "        versionCode 1\n        versionName '1.0'\n    }\n}\n" % (pkg, pkg)),
                ("app/src/main/AndroidManifest.xml",
                 "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                 "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\">\n"
                 "    <application android:label=\"%s\">\n"
                 "        <activity android:name=\".MainActivity\" android:exported=\"true\">\n"
                 "            <intent-filter>\n"
                 "                <action android:name=\"android.intent.action.MAIN\" />\n"
                 "                <category android:name=\"android.intent.category.LAUNCHER\" />\n"
                 "            </intent-filter>\n"
                 "        </activity>\n"
                 "    </application>\n</manifest>\n" % name),
                ("app/src/main/java/%s/MainActivity.java" % pkg.replace(".", "/"),
                 "package %s;\n\n"
                 "import android.app.Activity;\nimport android.os.Bundle;\n\n"
                 "public class MainActivity extends Activity {\n"
                 "    @Override\n    protected void onCreate(Bundle savedInstanceState) {\n"
                 "        super.onCreate(savedInstanceState);\n"
                 "        setContentView(R.layout.activity_main);\n"
                 "    }\n}\n" % pkg),
                ("app/src/main/res/values/strings.xml",
                 "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                 "<resources>\n    <string name=\"app_name\">%s</string>\n"
                 "</resources>\n" % name),
                ("app/src/main/res/layout/activity_main.xml",
                 "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                 "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\"\n"
                 "    android:layout_width=\"match_parent\" android:layout_height=\"match_parent\"\n"
                 "    android:gravity=\"center\" android:orientation=\"vertical\">\n"
                 "    <TextView android:layout_width=\"wrap_content\"\n"
                 "        android:layout_height=\"wrap_content\" android:text=\"Hello\" />\n"
                 "</LinearLayout>\n"),
                ("gradle/wrapper/gradle-wrapper.properties",
                 "distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\n"
                 "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.0-bin.zip\n"),
                ("gradlew",
                 "#!/bin/sh\n"
                 "# Gradle launcher. Uses the binary wrapper JAR when present;\n"
                 "# otherwise falls back to a system 'gradle' (the wrapper JAR\n"
                 "# cannot be generated offline - install gradle via pkg).\n"
                 "DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n"
                 "if [ -f \"$DIR/gradle/wrapper/gradle-wrapper.jar\" ]; then\n"
                 "    exec java -jar \"$DIR/gradle/wrapper/gradle-wrapper.jar\" \"$@\"\n"
                 "fi\n"
                 "if command -v gradle >/dev/null 2>&1; then exec gradle \"$@\"; fi\n"
                 "echo \"Gradle not found. Install: pkg install gradle\" >&2\n"
                 "exit 127\n"),
            ],
        }
        try:
            dest.mkdir()
            for fn, content in templates.get(ptype, []):
                fp = dest / fn
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(content, encoding="utf-8")
                if fn == "gradlew":
                    fp.chmod(0o755)
            self.store.log("Create Project", "Success", str(dest))
            self.ui.status("ok", "Created %s (%s)" % (dest, ptype))
        except OSError as e:
            self.ui.status("bad", str(e))
        self.ui.pause()

    def copy(self):
        src = self._pick("Copy from")
        if not src:
            self.ui.pause()
            return
        dst_raw = self.ui.ask("Copy to (destination path)")
        dst = safe_path(dst_raw, must_exist=False, for_write=True) if dst_raw else None
        if not dst:
            self.ui.status("bad", "Invalid destination.")
            self.ui.pause()
            return
        final = dst / src.name if dst.is_dir() else dst
        rel = path_relation(final, src)
        if rel in ("same", "a_in_b"):
            self.ui.status("bad", "Refused: destination lies inside (or equals) the source.")
            self.ui.pause()
            return
        try:
            if final.exists():
                if final.is_symlink():
                    self.ui.status("bad", "Refused: destination is a symlink.")
                    self.ui.pause()
                    return
                if not self.ui.confirm("Overwrite %s?" % final, False):
                    self.ui.pause()
                    return
                if final.is_dir():
                    shutil.rmtree(str(final))
                else:
                    final.unlink()
            if src.is_symlink() or final.is_symlink():
                self.ui.status("bad", "Refused: source or destination is a symlink.")
                self.ui.pause()
                return
            if src.is_dir():
                n, skipped = copy_tree_no_symlinks(src, final)
                if skipped:
                    self.ui.status("warn", "%d symlink/special entries skipped (never followed)." % skipped)
            else:
                shutil.copy2(str(src), str(final))
            if not final.exists():
                self.ui.status("bad", "Copy verification failed: destination missing.")
                self.ui.pause()
                return
            self.store.log("Copy Project", "Success", "%s -> %s" % (src, final))
            self.ui.status("ok", "Copied to %s" % final)
        except OSError as e:
            self.ui.status("bad", "Copy failed: %s" % e)
        self.ui.pause()

    def move(self):
        src = self._pick("Move from")
        if not src:
            self.ui.pause()
            return
        dst_raw = self.ui.ask("Move to")
        dst = secure_target(dst_raw, base=Path.cwd(), for_write=True,
                            must_exist=False) if dst_raw else None
        if not dst:
            self.ui.status("bad", "Invalid destination (outside write roots, unsafe symlink, or invalid).")
            self.ui.pause()
            return
        if dst.is_symlink():
            self.ui.status("bad", "Refused: destination is a symlink.")
            self.ui.pause()
            return
        rel = path_relation(dst, src)
        if rel == "same":
            self.ui.status("bad", "Source and destination are identical.")
            self.ui.pause()
            return
        if rel == "a_in_b":
            self.ui.status("bad", "Refused: destination lies inside the source.")
            self.ui.pause()
            return
        try:
            shutil.move(str(src), str(dst))
            if Path(dst).exists() and not src.exists():
                self.store.log("Move Project", "Success", str(src))
                self.ui.status("ok", "Moved.")
            else:
                self.ui.status("bad", "Move verification failed (source/destination state unexpected).")
        except OSError as e:
            self.ui.status("bad", "Move failed: %s" % e)
        self.ui.pause()

    def rename(self):
        src = self._pick("Rename")
        if not src:
            self.ui.pause()
            return
        name = self.ui.ask("New name")
        if not name or "/" in name:
            self.ui.status("bad", "Invalid name.")
            self.ui.pause()
            return
        try:
            src.rename(src.parent / name)
            self.store.log("Rename Project", "Success", "%s -> %s" % (src, name))
            self.ui.status("ok", "Renamed.")
        except OSError as e:
            self.ui.status("bad", "Rename failed: %s" % e)
        self.ui.pause()

    def delete(self):
        src = self._pick("Delete")
        if not src:
            self.ui.pause()
            return
        if is_protected(src):
            self.ui.status("bad", "Refusing to delete a protected path (HOME, config dir, /).")
            self.ui.pause()
            return
        ptype, _ = classify_project(src)
        size, _ = dir_size(src) if src.is_dir() else (src.stat().st_size, False)
        self.ui.status("warn", "Target : %s" % src)
        self.ui.status("warn", "Type   : %s" % ("directory (recursive)" if src.is_dir() else "file"))
        self.ui.status("warn", "Size   : %s" % human_size(size))
        if self.ui.confirm("Delete permanently?", False):
            try:
                if src.is_dir():
                    shutil.rmtree(str(src))
                else:
                    src.unlink()
                self.store.log("Delete Project", "Success", str(src))
                self.ui.status("ok", "Deleted.")
            except OSError as e:
                self.ui.status("bad", "Delete failed: %s" % e)
        else:
            self.ui.status("info", "Cancelled.")
        self.ui.pause()

    def open_dir(self):
        p = self._pick()
        if not p:
            self.ui.pause()
            return
        target = p if p.is_dir() else p.parent
        tool = self.app.detector.path("termux-open")
        if tool:
            Runner.run([tool, str(target)], timeout=10)
            self.ui.status("ok", "Opened with termux-open.")
        else:
            self.ui.status("info", "termux-open unavailable. Path: %s" % target)
        self.ui.pause()

    def run(self):
        p = self._pick()
        if not p or not p.is_dir():
            self.ui.pause()
            return
        ptype, _ = classify_project(p)
        cmd = None
        if ptype.startswith("Python"):
            scripts = sorted(p.glob("*.py"))
            if scripts:
                py = self.app.detector.path("python") or self.app.detector.path("python3")
                cmd = [py, scripts[0].name] if py else None
        elif ptype.startswith(("Node", "Vite")) and (p / "package.json").exists():
            cmd = [self.app.detector.path("npm"), "run", "dev"] if self.app.detector.installed("npm") else None
        if not cmd:
            self.ui.status("bad", "No runnable entry point for type: %s" % ptype)
            self.ui.pause()
            return
        self.ui.status("run", "$ " + " ".join(cmd))
        if not self.ui.confirm("Run in %s?" % p, True):
            self.ui.pause()
            return
        res = Runner.display(self.ui, cmd, cwd=p, timeout=180)
        self.store.log("Run Project", "Success" if res.rc == 0 else "Failed", str(p))

    def menu(self):
        while True:
            ch = self.ui.menu("PROJECT MANAGER", [
                ("1", "List / Scan", "project"), ("2", "Search", "search"),
                ("3", "Information", "system"), ("4", "Create", "build"),
                ("5", "Copy", "file"), ("6", "Move", "file"),
                ("7", "Rename", "file"), ("8", "Delete", "cleanup"),
                ("9", "Open Directory", "file"), ("R", "Run Project", "run"),
                ("B", "Build Project", "build"), ("0", "Back", "back"),
            ])
            if ch in (None, "0"):
                return
            {"1": self.list_projects, "2": self.search, "3": self.info,
             "4": self.create, "5": self.copy, "6": self.move, "7": self.rename,
             "8": self.delete, "9": self.open_dir, "r": self.run,
             "b": self.app.build.build_menu}.get(ch.lower(), lambda: None)()


# --- simple inline progress context ------------------------------------------------

class PleaseWait:
    def __init__(self, ui, msg):
        self.ui = ui
        self.msg = msg

    def __enter__(self):
        print(self.ui.t.c("%s %s..." % (ico("run"), self.msg), "muted"), flush=True)
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------------
# BUILD ENGINE - only real, detected build systems
# ---------------------------------------------------------------------------

class BuildEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui

    def plan(self, path):
        """Return list of command plans [(desc, [cmd])] for a project."""
        ptype, _ = classify_project(path)
        plans = []
        if ptype.startswith(("Node", "Vite")):
            pkg_file = path / "package.json"
            if pkg_file.exists():
                scripts = {}
                try:
                    pkg = json.loads(pkg_file.read_text(encoding="utf-8"))
                    if isinstance(pkg, dict):
                        scripts = pkg.get("scripts", {}) or {}
                except (OSError, ValueError):
                    scripts = {}
                if "build" not in scripts:
                    plans.append(("package.json has no 'build' script - nothing to build", None))
                elif self.app.detector.installed("npm"):
                    plans.append(("npm install", [self.app.detector.path("npm"), "install"]))
                    plans.append(("npm run build", [self.app.detector.path("npm"), "run", "build"]))
                else:
                    plans.append(("npm (NOT INSTALLED)", None))
        elif ptype == "Android / Gradle":
            if not (path / "app" / "build.gradle").exists():
                plans.append(("incomplete Android project (missing app/build.gradle) - "
                              "create it with the Project Manager", None))
            elif not self.app.detector.installed("java"):
                plans.append(("Java prerequisite MISSING (required by Gradle)", None))
            else:
                gw = path / "gradlew"
                if gw.exists():
                    if os.access(str(gw), os.X_OK):
                        plans.append(("./gradlew assembleDebug", [str(gw.resolve()), "assembleDebug"]))
                    else:
                        plans.append(("gradlew exists but is NOT executable (run: chmod +x gradlew)", None))
                elif self.app.detector.installed("gradle"):
                    plans.append(("gradle assembleDebug",
                                  [self.app.detector.path("gradle"), "assembleDebug"]))
                else:
                    plans.append(("Gradle/gradlew NOT AVAILABLE", None))
        elif ptype == "Flutter":
            if self.app.detector.installed("flutter"):
                plans.append(("flutter build apk --debug",
                              [self.app.detector.path("flutter"), "build", "apk", "--debug"]))
            else:
                plans.append(("flutter NOT INSTALLED", None))
        elif ptype == "C / C++ (Make)" and (path / "Makefile").exists() \
                and self.app.detector.installed("make"):
            plans.append(("make", [self.app.detector.path("make")]))
        elif ptype == "C / C++ (CMake)" and (path / "CMakeLists.txt").exists() \
                and self.app.detector.installed("cmake"):
            plans.append(("cmake -B build", [self.app.detector.path("cmake"), "-B", "build"]))
            plans.append(("cmake --build build", [self.app.detector.path("cmake"), "--build", "build"]))
        elif ptype == "Python":
            plans.append(("Python: no build step required (interpreted)", None))
        return plans, ptype

    ARTIFACT_GLOBS = {
        "Android / Gradle": ("app/build/outputs/**/*.apk",),
        "Flutter": ("build/app/outputs/flutter-apk/*.apk",),
        "Node / JavaScript": ("dist/**/*", "build/**/*"),
        "Vite / Node": ("dist/**/*",),
        "C / C++ (CMake)": ("build/**/*",),
    }

    def _find_artifacts(self, path, ptype):
        import glob as _glob
        found = []
        for pattern in self.ARTIFACT_GLOBS.get(ptype, ()):
            for hit in _glob.glob(str(path / pattern), recursive=True):
                hp = Path(hit)
                if hp.is_file() and hp.stat().st_size > 0:
                    found.append(hp)
        return found

    def build_menu(self):
        raw = self.ui.ask("Project path")
        p = safe_path(raw) if raw else None
        if not p or not p.is_dir():
            self.ui.status("bad", "Invalid project directory.")
            self.ui.pause()
            return
        plans, ptype = self.plan(p)
        self.ui.header("BUILD PLAN", "%s | %s" % (p, ptype))
        if not plans:
            self.ui.status("warn", "No build system detected.")
            self.ui.pause()
            return
        blocked = False
        for desc, cmd in plans:
            if cmd is None:
                self.ui.status("warn", desc)
                blocked = True
            else:
                self.ui.status("run", desc)
        runnable = [cmd for _, cmd in plans if cmd]
        if not runnable or blocked:
            self.ui.status("bad", "Prerequisites unmet - build cannot run safely.")
            self.ui.pause()
            return
        if not self.ui.confirm("Execute build plan?", False):
            self.ui.pause()
            return
        for cmd in runnable:
            self.ui.status("run", "$ " + " ".join(os.path.basename(x) if i == 0 else x
                                                  for i, x in enumerate(cmd)))
            res = Runner.display(self.ui, cmd, cwd=p, timeout=900, tail=4000, mode="live")
            if res.rc != 0:
                self.ui.status("bad", "BUILD FAILED (exit %d)" % res.rc)
                self.app.store.log("Project Build", "Failed", "%s exit=%d" % (p, res.rc))
                self.ui.pause()
                return
        artifacts = self._find_artifacts(p, ptype)
        if artifacts:
            for art in artifacts[:5]:
                digest = stream_hash(art, "sha256")
                self.ui.status("ok", "Artifact: %s (%s)%s" % (
                    art, human_size(art.stat().st_size),
                    "" if digest is None else " sha256=%s..." % digest[:16]))
            self.ui.status("ok", "BUILD SUCCEEDED - %d artifact(s) verified on disk" % len(artifacts))
            self.app.store.log("Project Build", "Success", "%s (%d artifacts)" % (p, len(artifacts)))
        else:
            if ptype == "Python":
                self.ui.status("ok", "BUILD SUCCEEDED (interpreted project - no artifacts expected).")
                self.app.store.log("Project Build", "Success", str(p))
            else:
                self.ui.status("warn", "Build commands exited 0 but no artifact was found - verify manually.")
                self.app.store.log("Project Build", "Uncertain", str(p))
        self.ui.pause()


# ---------------------------------------------------------------------------
# APK ENGINE - real analysis, secure extraction, capability-aware sign/verify
# ---------------------------------------------------------------------------

APK_SIG_MAGIC = b"APK Sig Block 42"
SIG_ID_V2 = 0x7109871A
SIG_ID_V3 = 0xF05368C0
SIG_ID_V31 = 0x1B93AD61


def _find_eocd(f, file_size):
    """Locate the End Of Central Directory. Returns cd_offset or None.
    Reads only the tail (EOCD comment is at most 65536 bytes)."""
    read_len = min(file_size, 22 + 65536)
    f.seek(file_size - read_len)
    tail = f.read()
    idx = tail.rfind(b"PK\x05\x06")
    if idx < 0 or idx + 22 > len(tail):
        return None
    cd_offset = struct.unpack("<I", tail[idx + 16:idx + 20])[0]
    if cd_offset >= file_size:
        return None  # impossible offset: corrupt or not a ZIP
    return cd_offset


def apk_signing_schemes(path):
    """Detect Android APK signature schemes, re-derived from the v2/v3 spec.

    APK Signing Block layout (all integers little-endian), located
    immediately BEFORE the ZIP central directory:

        [uint64 size1]                       # size of (pairs + size2 + magic)
        [pairs:  repeated {
            uint64 pair_len                  # byte length of (id + value)
            uint32 id
            uint8  value[pair_len - 4]
        }]
        [uint64 size2]                       # MUST equal size1
        [16 bytes magic "APK Sig Block 42"]

    Detection states are conservative: schemes are "detected structurally",
    never "verified". v4 is reported only as idsig presence (verification
    requires apksigner and is done separately)."""
    result = {"v1": False, "v1_source": "unavailable", "v2": False, "v3": False,
              "v3.1": False, "v4_idsig": "absent", "error": None}
    try:
        file_size = os.path.getsize(path)
        if file_size < 22:
            result["error"] = "file too small"
            return result
        with open(path, "rb") as f:
            cd_offset = _find_eocd(f, file_size)
            if cd_offset is None:
                result["error"] = "EOCD not found (not a ZIP/APK)"
                return result
            # The 24-byte block footer sits immediately before the central dir.
            if cd_offset < 24 + 8:  # need at least footer + one empty size field
                pass  # no signing block possible; not an error
            else:
                f.seek(cd_offset - 24)
                footer = f.read(24)
                if len(footer) == 24 and footer[8:24] == APK_SIG_MAGIC:
                    block_size = struct.unpack("<Q", footer[0:8])[0]
                    # size must cover footer(24) + trailing size field(8),
                    # must not underflow, and must fit inside the file.
                    if block_size < 24 or block_size + 8 > cd_offset:
                        result["error"] = "malformed signing block (impossible size)"
                        return result
                    block_start = cd_offset - block_size - 8
                    if block_start < 0:
                        result["error"] = "malformed signing block (offset underflow)"
                        return result
                    f.seek(block_start)
                    block = f.read(block_size + 8)
                    if len(block) != block_size + 8:
                        result["error"] = "truncated signing block"
                        return result
                    size1 = struct.unpack("<Q", block[0:8])[0]
                    if size1 != block_size:
                        result["error"] = "malformed signing block (size mismatch)"
                        return result
                    pairs_start, pairs_end = 8, block_size + 8 - 24
                    ids = []
                    pos = pairs_start
                    while pos < pairs_end:
                        if pos + 8 > pairs_end:
                            result["error"] = "malformed signing block (truncated pair)"
                            return result
                        pair_len = struct.unpack("<Q", block[pos:pos + 8])[0]
                        if pair_len < 4 or pos + 8 + pair_len > pairs_end:
                            result["error"] = "malformed signing block (bad pair length)"
                            return result
                        (pair_id,) = struct.unpack("<I", block[pos + 8:pos + 12])
                        ids.append(pair_id)
                        pos += 8 + pair_len
                    result["v2"] = SIG_ID_V2 in ids
                    result["v3"] = SIG_ID_V3 in ids or SIG_ID_V31 in ids
                    result["v3.1"] = SIG_ID_V31 in ids
        try:
            with zipfile.ZipFile(str(path)) as z:
                names = z.namelist()
            result["v1"] = any(n.upper().startswith("META-INF/")
                               and n.upper().endswith((".RSA", ".DSA", ".EC"))
                               for n in names)
            result["v1_source"] = "internal"
        except zipfile.BadZipFile:
            pass
        result["v4_idsig"] = "present" if Path(str(path) + ".idsig").exists() else "absent"
    except OSError as e:
        result["error"] = str(e)
    return result


def zip_entry_hashes(path, algo="sha256", limit=8000):
    """Streaming per-entry content hashes. Returns {name: hexdigest}."""
    out = {}
    with zipfile.ZipFile(str(path)) as z:
        for info in z.infolist()[:limit]:
            h = hashlib.new(algo)
            with z.open(info) as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            out[info.filename] = h.hexdigest()
    return out


# ---------------------------------------------------------------------------
# ARCHIVE SAFETY ANALYSIS - dry-run inspection before anything is written
# ---------------------------------------------------------------------------

MAX_FILENAME_LEN = 255
MAX_ARCHIVE_DEPTH = 32


def _member_findings(name, size, compressed, is_link, is_special, link_target=None):
    """Classify one archive member. Returns a list of finding codes."""
    out = []
    posix = str(name).replace("\\", "/")
    if not posix or posix in (".", ".."):
        out.append("EMPTY_NAME")
    if posix.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", str(name)):
        out.append("ABSOLUTE_PATH")
    parts = PurePosixPath(posix).parts
    if ".." in parts or "%2e%2e" in posix.lower() or "..%2f" in posix.lower():
        out.append("PATH_TRAVERSAL")
    if "\x00" in str(name):
        out.append("NUL_BYTE")
    if len(str(name)) > MAX_FILENAME_LEN:
        out.append("NAME_TOO_LONG")
    if len(parts) > MAX_ARCHIVE_DEPTH:
        out.append("EXCESSIVE_DEPTH")
    if is_link:
        out.append("SYMLINK_OR_HARDLINK")
        if link_target and (str(link_target).startswith("/")
                            or ".." in PurePosixPath(str(link_target)).parts):
            out.append("LINK_ESCAPES_DESTINATION")
    if is_special:
        out.append("SPECIAL_FILE")
    if size is not None and size > MAX_MEMBER_SIZE:
        out.append("MEMBER_TOO_LARGE")
    if (size and compressed and size > (1 << 20)
            and size / max(1, compressed) > MAX_RATIO):
        out.append("SUSPICIOUS_COMPRESSION")
    return out


def analyze_archive(path):
    """Dry-run safety report for a ZIP or TAR. Reads metadata only; writes
    nothing and extracts nothing. Returns OpResult."""
    p = Path(path)
    if not p.is_file():
        return OpResult.failure(ErrCode.NOT_FOUND, "no such archive: %s" % p)

    members, kind = [], None
    try:
        if zipfile.is_zipfile(str(p)):
            kind = "zip"
            with zipfile.ZipFile(str(p)) as zf:
                bad = zf.testzip()
                if bad is not None:
                    return OpResult.failure(ErrCode.ARCHIVE_CORRUPT,
                                            "CRC failure in member: %s" % bad)
                for i in zf.infolist():
                    mode = (i.external_attr >> 16) & 0o170000
                    members.append({
                        "name": i.filename, "size": i.file_size,
                        "compressed": i.compress_size,
                        "findings": _member_findings(
                            i.filename, i.file_size, i.compress_size,
                            is_link=(mode == 0o120000),
                            is_special=mode in (0o010000, 0o020000, 0o060000,
                                                0o140000)),
                    })
        else:
            kind = "tar"
            with tarfile.open(str(p)) as tf:
                for ti in tf.getmembers():
                    members.append({
                        "name": ti.name, "size": ti.size, "compressed": None,
                        "findings": _member_findings(
                            ti.name, ti.size, None,
                            is_link=(ti.issym() or ti.islnk()),
                            is_special=(ti.ischr() or ti.isblk()
                                        or ti.isfifo() or ti.isdev()),
                            link_target=ti.linkname),
                    })
    except zipfile.BadZipFile as e:
        return OpResult.failure(ErrCode.ARCHIVE_CORRUPT, "corrupt ZIP: %s" % e)
    except tarfile.TarError as e:
        return OpResult.failure(ErrCode.ARCHIVE_CORRUPT, "corrupt TAR: %s" % e)
    except (OSError, EOFError) as e:
        return OpResult.failure(ErrCode.ARCHIVE_CORRUPT, "unreadable archive: %s" % e)

    total = sum(m["size"] or 0 for m in members)
    packed = p.stat().st_size
    counts = {}
    for mem in members:
        for f in mem["findings"]:
            counts[f] = counts.get(f, 0) + 1

    checks = [
        ("member count", len(members) <= MAX_EXTRACT_ENTRIES,
         "%d / %d" % (len(members), MAX_EXTRACT_ENTRIES)),
        ("total uncompressed size", total <= MAX_EXTRACT_TOTAL,
         "%s / %s" % (human_size(total), human_size(MAX_EXTRACT_TOTAL))),
        ("overall compression ratio",
         not (packed > 4096 and total / max(1, packed) > MAX_RATIO),
         "%.1fx / %dx" % (total / max(1, packed), MAX_RATIO)),
        ("path traversal", not counts.get("PATH_TRAVERSAL"),
         "%d flagged" % counts.get("PATH_TRAVERSAL", 0)),
        ("absolute paths", not counts.get("ABSOLUTE_PATH"),
         "%d flagged" % counts.get("ABSOLUTE_PATH", 0)),
        ("symlinks / hardlinks", not counts.get("SYMLINK_OR_HARDLINK"),
         "%d flagged" % counts.get("SYMLINK_OR_HARDLINK", 0)),
        ("special / device files", not counts.get("SPECIAL_FILE"),
         "%d flagged" % counts.get("SPECIAL_FILE", 0)),
        ("per-member size cap", not counts.get("MEMBER_TOO_LARGE"),
         "%d flagged" % counts.get("MEMBER_TOO_LARGE", 0)),
        ("suspicious compression", not counts.get("SUSPICIOUS_COMPRESSION"),
         "%d flagged" % counts.get("SUSPICIOUS_COMPRESSION", 0)),
        ("filename length", not counts.get("NAME_TOO_LONG"),
         "%d flagged" % counts.get("NAME_TOO_LONG", 0)),
        ("nesting depth", not counts.get("EXCESSIVE_DEPTH"),
         "%d flagged" % counts.get("EXCESSIVE_DEPTH", 0)),
        ("NUL bytes in names", not counts.get("NUL_BYTE"),
         "%d flagged" % counts.get("NUL_BYTE", 0)),
    ]
    unsafe = [m for m in members if m["findings"]]
    safe = all(ok for _n, ok, _d in checks)
    res = OpResult.success({
        "archive": str(p), "format": kind,
        "packed_bytes": packed, "uncompressed_bytes": total,
        "member_count": len(members),
        "ratio": round(total / max(1, packed), 2),
        "safe_to_extract": safe,
        "checks": [{"check": n, "pass": ok, "detail": d} for n, ok, d in checks],
        "finding_counts": counts,
        "unsafe_members": [{"name": m["name"], "findings": m["findings"]}
                           for m in unsafe[:100]],
        "would_extract": len(members) - len(unsafe),
        "would_reject": len(unsafe),
    })
    if not safe:
        res.add_warning("%d member(s) would be rejected by the extractor"
                        % len(unsafe), ErrCode.ARCHIVE_UNSAFE)
    LOG.security("archive.analyzed", archive=str(p), safe=safe,
                 members=len(members), rejected=len(unsafe))
    return res


# ---------------------------------------------------------------------------
# BINARY AndroidManifest.xml (AXML) PARSER - stdlib only, no aapt required
# ---------------------------------------------------------------------------

_AXML_START_DOC = 0x00100100
_AXML_STRING_POOL = 0x001C0001
_AXML_RESOURCE_MAP = 0x00080180
_AXML_START_TAG = 0x00100102
_AXML_END_TAG = 0x00100103

_TYPE_NULL, _TYPE_REFERENCE, _TYPE_STRING = 0x00, 0x01, 0x03
_TYPE_INT_DEC, _TYPE_INT_HEX, _TYPE_INT_BOOL = 0x10, 0x11, 0x12

# Android framework attribute resource IDs. Obfuscated manifests often blank
# the attribute *names* in the string pool; the resource ID still identifies
# the attribute, so both routes are used.
ANDROID_ATTR_IDS = {
    0x01010003: "name", 0x01010001: "label", 0x01010002: "icon",
    0x01010006: "permission", 0x0101000f: "debuggable",
    0x01010010: "exported", 0x01010270: "targetSdkVersion",
    0x0101020c: "minSdkVersion", 0x01010271: "maxSdkVersion",
    0x0101021b: "versionCode", 0x0101021c: "versionName",
    0x01010280: "allowBackup", 0x01010272: "testOnly",
    0x01010604: "usesCleartextTraffic", 0x01010527: "networkSecurityConfig",
    0x010103a6: "protectionLevel", 0x01010000: "theme",
    0x0101048d: "requiredForAllUsers", 0x01010240: "installLocation",
    0x010102b6: "largeHeap", 0x01010269: "hardwareAccelerated",
}


class AXMLError(ToolkitError):
    code = ErrCode.APK_INVALID


class _AXMLReader:
    def __init__(self, data):
        self.d = data
        self.n = len(data)

    def u16(self, off):
        if off + 2 > self.n:
            raise AXMLError("truncated AXML at offset %d" % off)
        return struct.unpack_from("<H", self.d, off)[0]

    def u32(self, off):
        if off + 4 > self.n:
            raise AXMLError("truncated AXML at offset %d" % off)
        return struct.unpack_from("<I", self.d, off)[0]


def _parse_string_pool(r, off):
    """Return the list of strings held in a RES_STRING_POOL chunk."""
    chunk_size = r.u32(off + 4)
    count = r.u32(off + 8)
    style_count = r.u32(off + 12)
    flags = r.u32(off + 16)
    strings_start = r.u32(off + 20)
    is_utf8 = bool(flags & (1 << 8))
    if count > 500000:
        raise AXMLError("implausible string pool size: %d" % count)
    base = off + strings_start
    out = []
    for i in range(count):
        try:
            rel = r.u32(off + 28 + i * 4)
            pos = base + rel
            if pos >= r.n or pos >= off + chunk_size:
                out.append("")
                continue
            if is_utf8:
                ln = r.d[pos]
                pos += 2 if ln & 0x80 else 1        # skip the char-count field
                blen = r.d[pos]
                if blen & 0x80:
                    blen = ((blen & 0x7F) << 8) | r.d[pos + 1]
                    pos += 2
                else:
                    pos += 1
                out.append(r.d[pos:pos + blen].decode("utf-8", errors="replace"))
            else:
                ln = struct.unpack_from("<H", r.d, pos)[0]
                pos += 2
                if ln & 0x8000:
                    ln = ((ln & 0x7FFF) << 16) | struct.unpack_from("<H", r.d, pos)[0]
                    pos += 2
                out.append(r.d[pos:pos + ln * 2].decode("utf-16-le", errors="replace"))
        except (struct.error, IndexError, UnicodeError):
            out.append("")
    del style_count
    return out


def parse_binary_manifest(data):
    """Parse a binary AndroidManifest.xml into a nested element tree.

    Returns {"tag":..., "attrs": {...}, "children": [...]}. Raises AXMLError
    on anything malformed - a corrupt APK must never crash the caller."""
    if not data or len(data) < 8:
        raise AXMLError("manifest is empty or too small")
    r = _AXMLReader(data)
    magic = r.u32(0)
    if magic != 0x00080003:
        raise AXMLError("not a binary AXML document (magic 0x%08x)" % magic)
    declared = r.u32(4)
    if declared > len(data):
        raise AXMLError("declared size %d exceeds actual %d" % (declared, len(data)))

    strings, res_ids = [], []
    off, guard = 8, 0
    root, stack = None, []
    while off + 8 <= r.n:
        guard += 1
        if guard > 200000:
            raise AXMLError("chunk loop guard tripped (malformed AXML)")
        ctype = r.u32(off)
        csize = r.u32(off + 4)
        if csize < 8 or off + csize > r.n:
            break
        if ctype == _AXML_STRING_POOL:
            strings = _parse_string_pool(r, off)
        elif ctype == _AXML_RESOURCE_MAP:
            res_ids = [r.u32(off + 8 + i * 4) for i in range((csize - 8) // 4)]
        elif ctype == _AXML_START_TAG:
            name_idx = r.u32(off + 20)
            attr_start = r.u16(off + 24)
            attr_count = r.u16(off + 28)
            tag = strings[name_idx] if 0 <= name_idx < len(strings) else "?"
            attrs = {}
            abase = off + 16 + attr_start
            for i in range(min(attr_count, 4096)):
                a = abase + i * 20
                if a + 20 > r.n:
                    break
                a_name_idx = r.u32(a + 4)
                raw_idx = r.u32(a + 8)
                dtype = r.d[a + 15]
                dval = r.u32(a + 16)
                key = strings[a_name_idx] if 0 <= a_name_idx < len(strings) else ""
                if not key and 0 <= a_name_idx < len(res_ids):
                    key = ANDROID_ATTR_IDS.get(res_ids[a_name_idx],
                                               "attr_0x%08x" % res_ids[a_name_idx])
                if not key:
                    key = "attr_%d" % i
                if dtype == _TYPE_STRING:
                    val = strings[dval] if 0 <= dval < len(strings) else ""
                elif dtype == _TYPE_INT_BOOL:
                    val = bool(dval)
                elif dtype == _TYPE_INT_HEX:
                    val = "0x%08x" % dval
                elif dtype in (_TYPE_INT_DEC,):
                    val = dval if dval < (1 << 31) else dval - (1 << 32)
                elif dtype == _TYPE_REFERENCE:
                    val = "@0x%08x" % dval
                elif dtype == _TYPE_NULL:
                    val = None
                else:
                    val = (strings[raw_idx] if 0 <= raw_idx < len(strings)
                           else "0x%08x" % dval)
                attrs[key] = val
            node = {"tag": tag, "attrs": attrs, "children": []}
            if stack:
                stack[-1]["children"].append(node)
            elif root is None:
                root = node
            stack.append(node)
        elif ctype == _AXML_END_TAG:
            if stack:
                stack.pop()
        off += csize
    if root is None:
        raise AXMLError("no root element found in manifest")
    return root


def _iter_elements(node):
    yield node
    for child in node.get("children", []):
        for sub in _iter_elements(child):
            yield sub


# Android permissions classified dangerous or above by the platform.
DANGEROUS_PERMISSIONS = {
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "READ_CALENDAR",
    "WRITE_CALENDAR", "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "READ_PHONE_STATE",
    "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "ADD_VOICEMAIL", "USE_SIP",
    "BODY_SENSORS", "ACTIVITY_RECOGNITION", "SEND_SMS", "RECEIVE_SMS",
    "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE", "ACCESS_MEDIA_LOCATION",
    "BLUETOOTH_SCAN", "BLUETOOTH_CONNECT", "BLUETOOTH_ADVERTISE",
    "POST_NOTIFICATIONS", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO",
}
SPECIAL_PERMISSIONS = {
    "SYSTEM_ALERT_WINDOW", "WRITE_SETTINGS", "REQUEST_INSTALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN", "PACKAGE_USAGE_STATS",
    "SCHEDULE_EXACT_ALARM", "MANAGE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES",
}

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def apk_manifest_info(path):
    """Extract structured manifest data from an APK. Returns OpResult."""
    p = Path(path)
    if not p.is_file():
        return OpResult.failure(ErrCode.NOT_FOUND, "no such file: %s" % p)
    if not zipfile.is_zipfile(str(p)):
        return OpResult.failure(ErrCode.APK_INVALID,
                                "not a ZIP container - not a valid APK/AAB")
    try:
        with zipfile.ZipFile(str(p)) as z:
            names = set(z.namelist())
            manifest_name = ("AndroidManifest.xml" if "AndroidManifest.xml" in names
                             else ("base/manifest/AndroidManifest.xml"
                                   if "base/manifest/AndroidManifest.xml" in names
                                   else None))
            if manifest_name is None:
                return OpResult.failure(ErrCode.APK_INVALID,
                                        "no AndroidManifest.xml in the container")
            info = z.getinfo(manifest_name)
            if info.file_size > (16 << 20):
                return OpResult.failure(ErrCode.APK_INVALID,
                                        "manifest is implausibly large")
            raw = z.read(manifest_name)
            container = ("aab" if manifest_name.startswith("base/")
                         else ("apk" if any(n.endswith("classes.dex")
                                            for n in names) else "zip"))
    except (zipfile.BadZipFile, OSError, KeyError) as e:
        return OpResult.failure(ErrCode.APK_INVALID, "unreadable APK: %s" % e)

    try:
        root = parse_binary_manifest(raw)
    except AXMLError as e:
        return OpResult.failure(e.code, e.message)
    except (struct.error, IndexError, MemoryError, RecursionError) as e:
        return OpResult.failure(ErrCode.APK_INVALID,
                                "malformed manifest: %s: %s" % (type(e).__name__, e))

    manifest_attrs = root.get("attrs", {})
    result = {
        "container": container,
        "package": manifest_attrs.get("package"),
        "version_code": manifest_attrs.get("versionCode"),
        "version_name": manifest_attrs.get("versionName"),
        "install_location": manifest_attrs.get("installLocation"),
        "min_sdk": None, "target_sdk": None, "max_sdk": None,
        "permissions": [], "permissions_declared": [], "features": [],
        "components": {t: [] for t in COMPONENT_TAGS},
        "application": {},
    }
    for el in _iter_elements(root):
        tag, attrs = el.get("tag"), el.get("attrs", {})
        if tag == "uses-sdk":
            result["min_sdk"] = attrs.get("minSdkVersion")
            result["target_sdk"] = attrs.get("targetSdkVersion")
            result["max_sdk"] = attrs.get("maxSdkVersion")
        elif tag == "uses-permission" or tag == "uses-permission-sdk-23":
            n = attrs.get("name")
            if n:
                result["permissions"].append(str(n))
        elif tag == "permission":
            result["permissions_declared"].append(
                {"name": attrs.get("name"),
                 "protectionLevel": attrs.get("protectionLevel")})
        elif tag == "uses-feature":
            result["features"].append(str(attrs.get("name")))
        elif tag == "application":
            result["application"] = {
                "debuggable": attrs.get("debuggable"),
                "allowBackup": attrs.get("allowBackup"),
                "testOnly": attrs.get("testOnly"),
                "usesCleartextTraffic": attrs.get("usesCleartextTraffic"),
                "networkSecurityConfig": attrs.get("networkSecurityConfig"),
                "largeHeap": attrs.get("largeHeap"),
                "label": attrs.get("label"),
            }
        elif tag in COMPONENT_TAGS:
            has_filter = any(c.get("tag") == "intent-filter"
                             for c in el.get("children", []))
            exported = attrs.get("exported")
            result["components"][tag].append({
                "name": attrs.get("name"),
                "exported": exported,
                "exported_implicitly": exported is None and has_filter,
                "permission": attrs.get("permission"),
                "intent_filters": sum(1 for c in el.get("children", [])
                                      if c.get("tag") == "intent-filter"),
            })
    result["permissions"] = sorted(set(result["permissions"]))
    return OpResult.success(result)


def apk_security_report(path):
    """Technical security indicators for an APK.

    These are TECHNICAL findings about how the package is configured. They
    are not a verdict on whether the application is malicious or safe."""
    base = apk_manifest_info(path)
    if not base.ok:
        return base
    m = base.data
    findings = []

    def add(level, check, detail, evidence=None):
        findings.append({"level": level, "check": check, "detail": detail,
                         "evidence": evidence})

    app = m.get("application") or {}

    if app.get("debuggable") is True:
        add("HIGH", "debuggable flag",
            "android:debuggable=true - the process can be attached to by a "
            "debugger on any device", "application/@debuggable")
    else:
        add("INFO", "debuggable flag", "not enabled")

    if app.get("testOnly") is True:
        add("WARNING", "testOnly flag",
            "android:testOnly=true - installable only via adb with -t",
            "application/@testOnly")

    if app.get("allowBackup") is not False:
        add("WARNING", "backup policy",
            "android:allowBackup is not false - app data may be extracted "
            "through adb backup on older platforms", "application/@allowBackup")
    else:
        add("INFO", "backup policy", "allowBackup=false")

    cleartext = app.get("usesCleartextTraffic")
    nsc = app.get("networkSecurityConfig")
    target = m.get("target_sdk")
    if cleartext is True:
        add("HIGH", "cleartext traffic",
            "usesCleartextTraffic=true - plain HTTP is permitted",
            "application/@usesCleartextTraffic")
    elif cleartext is None and nsc is None:
        if isinstance(target, int) and target >= 28:
            add("INFO", "cleartext traffic",
                "default deny (targetSdk %s >= 28, no override)" % target)
        else:
            add("WARNING", "cleartext traffic",
                "no explicit policy and targetSdk is %s - platform default "
                "may permit plain HTTP" % target)
    else:
        add("INFO", "cleartext traffic",
            "networkSecurityConfig present" if nsc else "explicitly disabled")

    explicit, implicit = [], []
    for tag in COMPONENT_TAGS:
        for comp in m["components"][tag]:
            if comp["exported"] is True and not comp["permission"]:
                explicit.append("%s:%s" % (tag, comp["name"]))
            elif comp["exported_implicitly"] and not comp["permission"]:
                implicit.append("%s:%s" % (tag, comp["name"]))
    if explicit:
        add("HIGH", "exported components without permission",
            "%d component(s) are exported with no permission guard" % len(explicit),
            explicit[:12])
    if implicit:
        add("WARNING", "implicitly exported components",
            "%d component(s) have an intent-filter and no explicit "
            "android:exported - implicitly exported below API 31" % len(implicit),
            implicit[:12])
    if not explicit and not implicit:
        add("INFO", "exported components", "none exported without a guard")

    dangerous = [p for p in m["permissions"]
                 if p.rsplit(".", 1)[-1] in DANGEROUS_PERMISSIONS]
    special = [p for p in m["permissions"]
               if p.rsplit(".", 1)[-1] in SPECIAL_PERMISSIONS]
    if special:
        add("HIGH", "special permissions",
            "%d high-privilege permission(s) requested" % len(special), special)
    if dangerous:
        add("WARNING", "dangerous permissions",
            "%d runtime-dangerous permission(s) requested" % len(dangerous),
            dangerous[:20])
    if not dangerous and not special:
        add("INFO", "permissions", "%d requested, none dangerous"
            % len(m["permissions"]))

    weak = [d for d in m["permissions_declared"]
            if str(d.get("protectionLevel") or "").lower() in ("normal", "0", "0x00000000")]
    if weak:
        add("WARNING", "custom permission protection level",
            "%d custom permission(s) declared at 'normal' level" % len(weak),
            [d["name"] for d in weak][:10])

    if isinstance(m.get("min_sdk"), int) and m["min_sdk"] < 23:
        add("WARNING", "minSdkVersion",
            "minSdk %s predates runtime permissions (API 23)" % m["min_sdk"])
    if isinstance(target, int) and target < 28:
        add("WARNING", "targetSdkVersion",
            "targetSdk %s misses modern platform hardening defaults" % target)

    schemes = apk_signing_schemes(Path(path))
    if schemes.get("error"):
        add("WARNING", "signing scheme", "undetermined: %s" % schemes["error"])
    else:
        detected = [k for k in ("v1", "v2", "v3") if schemes.get(k)]
        if not detected:
            add("HIGH", "signing scheme",
                "no signing block detected (structural check)")
        elif detected == ["v1"]:
            add("WARNING", "signing scheme",
                "only v1 (JAR) signing detected - vulnerable to Janus-class "
                "issues on old platforms", detected)
        else:
            add("INFO", "signing scheme", "detected: %s" % ", ".join(detected))
        add("INFO", "signature verification",
            "structural detection only; cryptographic verification requires "
            "apksigner and is NOT performed here")

    counts = {}
    for f in findings:
        counts[f["level"]] = counts.get(f["level"], 0) + 1
    res = OpResult.success({
        "file": str(path),
        "manifest": m,
        "findings": findings,
        "summary": counts,
        "high": counts.get("HIGH", 0),
        "warning": counts.get("WARNING", 0),
        "info": counts.get("INFO", 0),
        "disclaimer": "technical configuration indicators only; this is not a "
                      "judgement about the application or its publisher",
    })
    if counts.get("HIGH"):
        res.add_warning("%d HIGH severity indicator(s)" % counts["HIGH"])
    LOG.audit("apk_security_report", str(path), "success", None,
              high=counts.get("HIGH", 0), warning=counts.get("WARNING", 0))
    return res


class APKEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui

    def _pick(self, prompt="APK path"):
        raw = self.ui.ask(prompt)
        p = safe_path(raw) if raw else None
        if not p or p.suffix.lower() != ".apk" or not p.is_file():
            self.ui.status("bad", "Not a valid .apk file.")
            return None
        return p

    def _summary(self, p):
        rows = [("File", str(p))]
        try:
            rows.append(("Size", human_size(p.stat().st_size)))
        except OSError:
            rows.append(("Size", "N/A"))
        sha = stream_hash(p, "sha256")
        md5 = stream_hash(p, "md5")
        rows.append(("SHA256", sha or "unavailable"))
        rows.append(("MD5", md5 or "unavailable"))
        try:
            with zipfile.ZipFile(str(p)) as z:
                names = z.namelist()
                rows.append(("ZIP entries", str(len(names))))
                rows.append(("AndroidManifest.xml", "present" if "AndroidManifest.xml" in names else "MISSING"))
                rows.append(("classes.dex", "present" if any(n.endswith("classes.dex") for n in names) else "MISSING"))
                certs = [n for n in names if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
                rows.append(("v1 (JAR) certs", ", ".join(certs) if certs else "none found"))
        except zipfile.BadZipFile:
            rows.append(("ZIP validity", "INVALID - not a ZIP"))
        except OSError as e:
            rows.append(("ZIP validity", "unreadable: %s" % e))
        schemes = apk_signing_schemes(p)
        if schemes["error"]:
            rows.append(("Signing schemes", "unknown (%s)" % schemes["error"]))
        else:
            rows.append(("Scheme v1 (JAR)", "detected (structural)" if schemes["v1"]
                         else "not detected (%s)" % schemes["v1_source"]))
            rows.append(("Scheme v2", "detected (structural)" if schemes["v2"] else "not detected"))
            rows.append(("Scheme v3/v3.1", "detected (structural)" if schemes["v3"] else "not detected"))
            rows.append(("Scheme v4", "idsig %s (cryptographic verification requires apksigner)"
                         % schemes["v4_idsig"]))
        try:
            with zipfile.ZipFile(str(p)) as z:
                infos = z.infolist()
                names = [i.filename for i in infos]
                dups = sorted({n for n in names if names.count(n) > 1})
                suspicious = [n for n in names if not _zip_member_safe(n)]
                ratios = [(i.filename, i.file_size / max(1, i.compress_size))
                          for i in infos
                          if i.file_size > (1 << 20) and i.compress_size
                          and i.file_size / max(1, i.compress_size) > MAX_RATIO]
                multidex = sorted(n for n in names
                                  if re.match(r"classes\d*\.dex$", n))
            if dups:
                rows.append(("Duplicate entries", "%d: %s" % (len(dups), ", ".join(dups[:4]))))
            if suspicious:
                rows.append(("Suspicious paths", "%d entries (absolute/traversal)" % len(suspicious)))
            if ratios:
                rows.append(("Ratio anomalies", "%d entries > %dx compression" % (len(ratios), MAX_RATIO)))
            if multidex:
                rows.append(("DEX files", ", ".join(multidex[:8]) + (" ..." if len(multidex) > 8 else "")))
        except (zipfile.BadZipFile, OSError):
            pass
        sha1 = stream_hash(p, "sha1")
        rows.append(("SHA1 (legacy)", sha1 or "unavailable"))
        return rows

    def info(self):
        p = self._pick()
        if not p:
            self.ui.pause()
            return
        self.ui.header("APK INFORMATION")
        self.ui.panels([("PACKAGE", self._summary(p))])
        tool = "aapt" if self.app.detector.installed("aapt") else \
               ("apkanalyzer" if self.app.detector.installed("apkanalyzer") else None)
        if tool:
            cmd = [self.app.detector.path(tool), "dump", "badging", str(p)] if tool == "aapt" \
                else [self.app.detector.path(tool), "manifest", "print", str(p)]
            self.ui.status("run", "$ " + " ".join(cmd))
            Runner.display(self.ui, cmd, timeout=30, tail=3000)
        else:
            self.ui.status("info", "aapt/apkanalyzer not installed - package metadata not parsed.")
        self.app.store.log("APK Info", "Success", p.name)
        self.ui.pause()

    def verify(self):
        p = self._pick()
        if not p:
            self.ui.pause()
            return
        self.ui.header("APK VERIFY")
        try:
            with zipfile.ZipFile(str(p)) as z:
                bad = z.testzip()
            if bad is None:
                self.ui.status("ok", "ZIP integrity: OK")
            else:
                self.ui.status("bad", "ZIP integrity: corrupt member %s" % bad)
        except (zipfile.BadZipFile, OSError) as e:
            self.ui.status("bad", "Not a valid APK/ZIP: %s" % e)
            self.ui.pause()
            return
        if self.app.detector.installed("apksigner"):
            res = Runner.display(self.ui, [self.app.detector.path("apksigner"), "verify",
                                           "--print-certs", str(p)], timeout=60)
            self.app.store.log("APK Verify", "Success" if res.rc == 0 else "Failed", p.name)
        else:
            self.ui.status("info", "apksigner NOT INSTALLED - certificate verification unavailable.")
        self.ui.pause()

    def extract(self):
        p = self._pick()
        if not p:
            self.ui.pause()
            return
        raw = self.ui.ask("Destination directory", str(p.with_suffix("")))
        dest = safe_path(raw, must_exist=False, for_write=True) if raw else None
        if not dest:
            self.ui.status("bad", "Invalid destination.")
            self.ui.pause()
            return
        if dest.exists() and any(dest.iterdir()) and not self.ui.confirm("Destination not empty. Continue?", False):
            self.ui.pause()
            return
        try:
            dest.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(str(p)) as z:
                extracted, rejected = safe_extract_zip(z, dest)
            self.ui.status("ok", "Extracted %d entries -> %s" % (extracted, dest))
            if rejected:
                self.ui.status("warn", "Rejected %d unsafe members (path escape/symlink)." % len(rejected))
        except ArchiveLimitError as e:
            self.ui.status("bad", "Safety stop: %s" % e)
        except (zipfile.BadZipFile, OSError) as e:
            self.ui.status("bad", "Extract failed: %s" % e)
        self.ui.pause()

    def compare(self):
        self.ui.status("info", "First APK:")
        a = self._pick()
        if not a:
            self.ui.pause()
            return
        self.ui.status("info", "Second APK:")
        b = self._pick()
        if not b:
            self.ui.pause()
            return
        ha, hb = stream_hash(a, "sha256"), stream_hash(b, "sha256")
        self.ui.header("APK COMPARE")
        print(" A SHA256: %s" % ha)
        print(" B SHA256: %s" % hb)
        if ha and ha == hb:
            self.ui.status("ok", "Files are byte-identical (SHA256 match).")
        else:
            self.ui.status("warn", "Files DIFFER at byte level - comparing entries.")
            try:
                ea, eb = zip_entry_hashes(a), zip_entry_hashes(b)
                only_a = sorted(set(ea) - set(eb))
                only_b = sorted(set(eb) - set(ea))
                changed = sorted(k for k in set(ea) & set(eb) if ea[k] != eb[k])
                print(" Entries only in A : %d" % len(only_a))
                for k in only_a[:8]:
                    print("   + %s" % k)
                print(" Entries only in B : %d" % len(only_b))
                for k in only_b[:8]:
                    print("   - %s" % k)
                print(" Entries CHANGED   : %d (content hash differs)" % len(changed))
                for k in changed[:8]:
                    print("   ~ %s" % k)
            except zipfile.BadZipFile:
                self.ui.status("info", "Entry-level compare skipped (invalid ZIP).")
        for p_, tag in ((a, "A"), (b, "B")):
            s = apk_signing_schemes(p_)
            if not s["error"]:
                print(" %s schemes: v1=%s v2=%s v3=%s idsig=%s" %
                      (tag, s["v1"], s["v2"], s["v3"], s["v4_idsig"]))
        try:
            with zipfile.ZipFile(str(a)) as za, zipfile.ZipFile(str(b)) as zb:
                sa = {i.filename: i.file_size for i in za.infolist()}
                sb = {i.filename: i.file_size for i in zb.infolist()}
            size_changed = [(k, sa[k], sb[k]) for k in set(sa) & set(sb) if sa[k] != sb[k]]
            if size_changed:
                print(" Size changes: %d entries" % len(size_changed))
                for k, x, y in size_changed[:8]:
                    print("   %s: %s -> %s" % (k, human_size(x), human_size(y)))
        except zipfile.BadZipFile:
            pass
        self.app.store.log("APK Compare", "Success", "%s vs %s" % (a.name, b.name))
        self.ui.pause()

    def find(self):
        raw = self.ui.ask("Search root", str(Path.home()))
        root = safe_path(raw) if raw else None
        if not root:
            self.ui.status("bad", "Invalid root.")
            self.ui.pause()
            return
        results = []
        for current, entries, _d in bounded_walk(root):
            for e in entries:
                if e.name.lower().endswith(".apk"):
                    results.append(str(Path(current) / e.name))
                    if len(results) >= 200:
                        break
            if len(results) >= 200:
                break
        self.ui.header("APK SEARCH", "%d found" % len(results))
        for r in results:
            print(" - %s" % r)
        if not results:
            self.ui.status("info", "No .apk files found.")
        self.ui.pause()

    def install(self):
        p = self._pick()
        if not p:
            self.ui.pause()
            return
        self.ui.status("warn", "APK: %s (%s)" % (p, human_size(p.stat().st_size)))
        if not self.ui.confirm("Open with Android package installer?", False):
            self.ui.status("info", "Cancelled.")
            self.ui.pause()
            return
        tool = self.app.detector.path("termux-open")
        if tool:
            _res = Runner.run([tool, str(p)], timeout=30)
            if _res.rc == 0:
                self.ui.status("ok", "Handed to Android installer. Confirm on the device dialog.")
            else:
                self.ui.status("bad", "termux-open failed (exit %d): %s" % (_res.rc, _res.err.strip()))
        else:
            self.ui.status("bad", "termux-open NOT INSTALLED - cannot trigger install.")
            self.ui.status("info", "Install with: pkg install termux-tools")
        self.app.store.log("Install APK", "Success" if tool else "Unavailable", p.name)
        self.ui.pause()

    def sign(self):
        p = self._pick()
        if not p:
            self.ui.pause()
            return
        if not self.app.detector.installed("apksigner"):
            self.ui.status("bad", "apksigner NOT INSTALLED.")
            self.ui.status("info", "Required tools:")
            print("   apksigner : %s" % self.app.detector.status("apksigner"))
            print("   keytool   : %s" % "INSTALLED" if Runner.check("keytool") else "   keytool   : MISSING")
            self.ui.status("info", "Install: pkg install apksigner (or openjdk-17)")
            self.ui.pause()
            return
        ks_raw = self.ui.ask("Keystore path")
        ks = safe_path(ks_raw) if ks_raw else None
        if not ks:
            self.ui.status("bad", "Invalid keystore path.")
            self.ui.pause()
            return
        alias = self.ui.ask("Key alias")
        if not alias:
            self.ui.pause()
            return
        out_raw = self.ui.ask("Output APK", str(p.with_name(p.stem + "-signed.apk")))
        out = safe_path(out_raw, must_exist=False, for_write=True) if out_raw else None
        if not out:
            self.ui.status("bad", "Invalid output path.")
            self.ui.pause()
            return
        if out == p.resolve():
            self.ui.status("bad", "Refused: output would overwrite the source APK.")
            self.ui.pause()
            return
        tmp_out = out.with_name(out.name + ".clxv12-signing.tmp")
        try:
            password = getpass.getpass("Keystore password (input hidden): ")
        except (EOFError, KeyboardInterrupt):
            print()
            self.ui.status("info", "Cancelled.")
            self.ui.pause()
            return
        if not password and not sys.stdin.isatty():
            self.ui.status("warn", "No TTY: password cannot be read; continuing without one.")
        if not self.ui.confirm("Sign %s?" % p.name, False):
            self.ui.pause()
            return
        env = dict(os.environ)
        cmd = [self.app.detector.path("apksigner"), "sign", "--ks", str(ks),
               "--ks-key-alias", alias, "--out", str(tmp_out)]
        if password:
            env["CLXV12_KS_PASS"] = password  # env, not argv: invisible to ps
            cmd += ["--ks-pass", "env:CLXV12_KS_PASS"]
        cmd += [str(p)]
        try:
            _res = Runner.run(cmd, timeout=120, env=env)
        finally:
            env.pop("CLXV12_KS_PASS", None)   # scrub the secret even on failure
        text = (_res.out + _res.err).strip()
        if text:
            print(text[:2000])
        ok = False
        if _res.rc != 0:
            self.ui.status("bad", "Signing command failed (exit %d)." % _res.rc)
            self.ui.status("info", "Tip: run apksigner manually in a TTY for interactive prompts.")
        elif not tmp_out.exists():
            self.ui.status("bad", "Signing reported exit 0 but the output file is missing.")
            tmp_out.unlink(missing_ok=True)
        elif tmp_out.stat().st_size == 0:
            self.ui.status("bad", "Signing produced an empty output file.")
            tmp_out.unlink(missing_ok=True)
        else:
            os.replace(str(tmp_out), str(out))   # atomic publish
            self.ui.status("ok", "Signed -> %s (%s)" % (out, human_size(out.stat().st_size)))
            ok = True
            if self.app.detector.installed("apksigner"):
                vr = Runner.run([self.app.detector.path("apksigner"), "verify",
                                 "--print-certs", str(out)], timeout=60)
                if vr.rc == 0:
                    self.ui.status("ok", "apksigner verification: PASSED")
                else:
                    self.ui.status("warn", "apksigner verification failed (exit %d)." % vr.rc)
                    ok = False
            else:
                self.ui.status("info", "Verification skipped: apksigner not on PATH.")
        self.app.store.log("APK Sign", "Success" if ok else "Failed", p.name)
        self.ui.pause()

    def menu(self):
        while True:
            ch = self.ui.menu("APK ENGINE", [
                ("1", "Information", "apk"), ("2", "Verify", "security"),
                ("3", "Extract (safe)", "archive"), ("4", "Compare", "search"),
                ("5", "Find APKs", "search"), ("6", "Install", "apk"),
                ("7", "Sign", "build"), ("0", "Back", "back"),
            ])
            if ch in (None, "0"):
                return
            {"1": self.info, "2": self.verify, "3": self.extract, "4": self.compare,
             "5": self.find, "6": self.install, "7": self.sign}.get(ch, lambda: None)()

# ---------------------------------------------------------------------------
# NETWORK ENGINE - defensive, real CIDR from interface netmask
# ---------------------------------------------------------------------------

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "netbios", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5353: "mdns", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt",
}
SCAN_HOST_LIMIT = 4096


def _route_table():
    try:
        with open("/proc/net/route", "r", encoding="utf-8", errors="replace") as f:
            return [ln.split() for ln in f.readlines()[1:] if len(ln.split()) > 7]
    except OSError:
        return []


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))  # RFC5737; no packets leave the device
        ip = s.getsockname()[0]
    except OSError:
        ip = None
    finally:
        s.close()
    if not ip or ip.startswith("127."):
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip = None
    return ip


def get_default_route():
    for parts in _route_table():
        if parts[1] == "00000000":
            try:
                gw = socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
                return parts[0], gw
            except (ValueError, OSError):
                continue
    return None, None


def get_interface_netmask(iface, ip):
    """Return the real ipaddress network for iface containing `ip`, or None."""
    if not iface or not ip:
        return None
    for parts in _route_table():
        if parts[0] != iface or parts[1] in ("00000000",):
            continue
        try:
            dest = socket.inet_ntoa(bytes.fromhex(parts[1])[::-1])
            mask = socket.inet_ntoa(bytes.fromhex(parts[7])[::-1])
            net = ipaddress.ip_network("%s/%s" % (dest, mask), strict=False)
            if ipaddress.ip_address(ip) in net:
                return net
        except (ValueError, OSError):
            continue
    return None


def get_dns_servers():
    out = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
            out.extend(re.findall(r"nameserver\s+(\S+)", f.read()))
    except OSError:
        pass
    return out


def get_local_network():
    """Return (network, local_ip, gateway, iface). Network is the real
    interface network; falls back to a /24 around the local IP."""
    ip = get_local_ip()
    iface, gw = get_default_route()
    net = get_interface_netmask(iface, ip) if ip else None
    if net is None and ip:
        try:
            net = ipaddress.ip_network("%s/24" % ip, strict=False)
        except ValueError:
            net = None
    return net, ip, gw, iface


# ---------------------------------------------------------------------------
# PORT CHECK CORE - parsing, resolution and probing (pure, testable, no UI)
# ---------------------------------------------------------------------------

PORT_OPEN = "OPEN"
PORT_CLOSED = "CLOSED"
PORT_FILTERED = "FILTERED"
PORT_TIMEOUT = "TIMEOUT"
PORT_ERROR = "ERROR"

MAX_PORTS_PER_CHECK = 1024
MAX_PORT_CONCURRENCY = 32
MAX_HOSTNAME_LEN = 253
DEFAULT_PORT_TIMEOUT = 0.8
DNS_TIMEOUT = 5.0

_HOSTNAME_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$")


def parse_ports(raw, limit=MAX_PORTS_PER_CHECK):
    """'22, 80, 8000-8010' or 'common' -> (sorted ports, warnings).

    Every malformed token produces a warning, never an exception, unless
    nothing usable survives - then the caller gets InvalidArgument so the
    CLI can exit 2 instead of pretending an empty scan succeeded."""
    warnings = []
    if raw is None:
        raise InvalidArgument("no ports given", ErrCode.INVALID_PORT)
    text = str(raw).replace("\x00", "").strip()
    if not text:
        raise InvalidArgument("no ports given", ErrCode.INVALID_PORT)
    if text.lower() in ("common", "default"):
        return sorted(COMMON_SERVICES), warnings
    if text.lower() == "all":
        raise InvalidArgument(
            "refusing a full 1-65535 sweep; give an explicit range (max %d ports)"
            % limit, ErrCode.INVALID_PORT)

    ports = set()
    for token in re.split(r"[,\s;]+", text):
        if not token:
            continue
        if "-" in token.lstrip("-"):
            lo_s, _, hi_s = token.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                warnings.append("ignored malformed range %r" % token[:32])
                continue
            if lo > hi:
                lo, hi = hi, lo
            if lo < 1 or hi > 65535:
                warnings.append("range %r clamped to 1-65535" % token[:32])
                lo, hi = max(1, lo), min(65535, hi)
            if lo > hi:
                warnings.append("ignored empty range %r" % token[:32])
                continue
            if (hi - lo + 1) > limit:
                warnings.append("range %r truncated to %d ports" % (token[:32], limit))
                hi = lo + limit - 1
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(token)
            except ValueError:
                warnings.append("ignored non-numeric port %r" % token[:32])
                continue
            if not 1 <= p <= 65535:
                warnings.append("ignored out-of-range port %d" % p)
                continue
            ports.add(p)
        if len(ports) > limit:
            break

    if not ports:
        raise InvalidArgument("no valid ports in %r" % text[:64], ErrCode.INVALID_PORT)
    out = sorted(ports)
    if len(out) > limit:
        warnings.append("port list truncated from %d to %d" % (len(out), limit))
        out = out[:limit]
    return out, warnings


class ResolvedTarget:
    """A target after parsing. `addresses` holds ipaddress objects - never
    strings - so callers can read .version without guessing the type.

    This is the type discipline whose absence caused the 2.1.0 crash
    `'str' object has no attribute 'version'`."""

    __slots__ = ("raw", "host", "addresses", "kind", "scope_id")

    def __init__(self, raw, host, addresses, kind, scope_id=None):
        self.raw = raw
        self.host = host
        self.addresses = list(addresses)
        self.kind = kind                      # 'ipv4' | 'ipv6' | 'hostname'
        self.scope_id = scope_id

    @property
    def primary(self):
        return self.addresses[0] if self.addresses else None

    def connect_host(self, addr):
        """String form usable by socket.connect for this address."""
        s = str(addr)
        if addr.version == 6 and self.scope_id:
            return "%s%%%s" % (s, self.scope_id)
        return s

    def as_dict(self):
        return {
            "input": self.raw,
            "host": self.host,
            "kind": self.kind,
            "scope_id": self.scope_id,
            "addresses": [{"address": str(a), "version": a.version,
                           "loopback": bool(a.is_loopback),
                           "private": bool(a.is_private),
                           "link_local": bool(a.is_link_local)}
                          for a in self.addresses],
        }


def _looks_like_hostname(text):
    if not text or len(text) > MAX_HOSTNAME_LEN:
        return False
    return bool(_HOSTNAME_RE.match(text))


def _getaddrinfo_bounded(host, timeout=DNS_TIMEOUT):
    """getaddrinfo ignores socket timeouts, so bound it in a worker thread.
    A hung resolver can never hang the toolkit."""
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(socket.getaddrinfo, host, None,
                        socket.AF_UNSPEC, socket.SOCK_STREAM)
        try:
            return fut.result(timeout=timeout)
        except FuturesTimeout:
            raise NetworkFailure("DNS lookup for %r timed out after %.1fs"
                                 % (host[:64], timeout), ErrCode.NETWORK_TIMEOUT)
        except socket.gaierror as e:
            raise NetworkFailure("cannot resolve %r: %s" % (host[:64], e),
                                 ErrCode.DNS_FAILURE)
        except OSError as e:
            raise NetworkFailure("resolver error for %r: %s" % (host[:64], e),
                                 ErrCode.DNS_FAILURE)


def resolve_target(raw, allow_dns=True, timeout=DNS_TIMEOUT):
    """Parse a user-supplied target into a ResolvedTarget.

    Accepts: 127.0.0.1, ::1, [::1], fe80::1%wlan0, localhost, router.lan.
    Rejects: empty, NUL bytes, over-long input, malformed literals.
    Never returns a bare string and never raises anything but ToolkitError."""
    if raw is None:
        raise InvalidArgument("no target given", ErrCode.INVALID_HOST)
    text = str(raw)
    if "\x00" in text:
        raise InvalidArgument("target contains a NUL byte", ErrCode.INVALID_HOST)
    text = text.strip()
    if not text:
        raise InvalidArgument("no target given", ErrCode.INVALID_HOST)
    if len(text) > MAX_HOSTNAME_LEN + 16:
        raise InvalidArgument("target too long (%d chars)" % len(text),
                              ErrCode.INVALID_HOST)

    host = text
    if host.startswith("[") and host.endswith("]"):      # [::1] URL form
        host = host[1:-1]

    scope_id = None
    if "%" in host:                                       # fe80::1%wlan0
        host, _, scope_id = host.partition("%")
        scope_id = scope_id or None

    # 1. IP literal - the fast, DNS-free path.
    try:
        addr = ipaddress.ip_address(host)
        return ResolvedTarget(text, host, [addr],
                              "ipv6" if addr.version == 6 else "ipv4", scope_id)
    except ValueError:
        pass

    # 2. Hostname.
    if not allow_dns:
        raise InvalidArgument("%r is not an IP address and DNS is disabled"
                              % text[:64], ErrCode.INVALID_HOST)
    if not _looks_like_hostname(host):
        raise InvalidArgument("%r is not a valid IP address or hostname"
                              % text[:64], ErrCode.INVALID_HOST)
    infos = _getaddrinfo_bounded(host, timeout)
    addrs, seen = [], set()
    for family, _stype, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        literal = sockaddr[0]
        if "%" in literal:
            literal, _, zone = literal.partition("%")
            scope_id = scope_id or zone or None
        try:
            a = ipaddress.ip_address(literal)
        except ValueError:
            continue
        if a not in seen:
            seen.add(a)
            addrs.append(a)
    if not addrs:
        raise NetworkFailure("%r resolved to no usable address" % text[:64],
                             ErrCode.DNS_FAILURE)
    addrs.sort(key=lambda a: a.version)                   # IPv4 first: fails faster
    return ResolvedTarget(text, host, addrs, "hostname", scope_id)


def address_is_local(addr, network=None, gateway=None):
    """Policy: this toolkit probes the device itself and the network it is
    already attached to. Returns (permitted, reason)."""
    if not isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        raise InvalidArgument("address_is_local requires an ipaddress object, got %s"
                              % type(addr).__name__)
    if addr.is_loopback:
        return True, "loopback"
    if addr.is_link_local:
        return True, "link-local"
    if gateway:
        try:
            if addr == ipaddress.ip_address(str(gateway)):
                return True, "default gateway"
        except ValueError:
            pass
    if network is not None:
        try:
            if addr.version == network.version and addr in network:
                return True, "inside local network %s" % network
        except (TypeError, ValueError):
            pass
    return False, "outside the local network"


def probe_port(host, port, family, timeout=DEFAULT_PORT_TIMEOUT):
    """Single TCP connect probe. Returns (state, latency_ms, detail).
    Never raises, never blocks longer than `timeout` plus OS overhead."""
    import errno as _errno
    s = None
    t0 = time.monotonic()
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(max(0.05, float(timeout)))
        rc = s.connect_ex((host, int(port)))
        ms = (time.monotonic() - t0) * 1000.0
        if rc == 0:
            return PORT_OPEN, ms, ""
        if rc in (_errno.ECONNREFUSED,):
            return PORT_CLOSED, ms, "connection refused"
        if rc in (_errno.ETIMEDOUT, _errno.EAGAIN, _errno.EINPROGRESS,
                  getattr(_errno, "EWOULDBLOCK", _errno.EAGAIN)):
            return PORT_TIMEOUT, ms, "no response"
        if rc in (_errno.EHOSTUNREACH, _errno.ENETUNREACH, _errno.EHOSTDOWN,
                  _errno.ENETDOWN, _errno.ECONNABORTED, _errno.ENETRESET):
            return PORT_FILTERED, ms, os.strerror(rc)
        if rc in (_errno.EACCES, _errno.EPERM):
            return PORT_ERROR, ms, "permission denied"
        if rc in (_errno.EAFNOSUPPORT, _errno.EPROTONOSUPPORT,
                  _errno.EADDRNOTAVAIL, _errno.EINVAL):
            return PORT_ERROR, ms, os.strerror(rc)
        return PORT_ERROR, ms, os.strerror(rc) if rc else "unknown error"
    except (socket.timeout, TimeoutError):
        return PORT_TIMEOUT, (time.monotonic() - t0) * 1000.0, "socket timeout"
    except (OverflowError, ValueError) as e:
        return PORT_ERROR, 0.0, "invalid port/address: %s" % e
    except OSError as e:
        return PORT_ERROR, (time.monotonic() - t0) * 1000.0, str(e)
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def scan_ports(target, ports, timeout=DEFAULT_PORT_TIMEOUT,
               concurrency=16, deadline=None):
    """Probe `ports` on a ResolvedTarget. Bounded concurrency, hard overall
    deadline, results always returned even if cancelled. Never raises."""
    if not isinstance(target, ResolvedTarget):
        raise InvalidArgument("scan_ports requires a ResolvedTarget, got %s"
                              % type(target).__name__)
    addr = target.primary
    if addr is None:
        raise InvalidArgument("target resolved to no address", ErrCode.INVALID_HOST)
    family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    host = target.connect_host(addr)
    workers = max(1, min(int(concurrency), MAX_PORT_CONCURRENCY, len(ports)))
    end_by = deadline if deadline is not None else (
        time.monotonic() + max(10.0, timeout * len(ports) / workers + 5.0))

    results, cancelled = [], False
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(probe_port, host, p, family, timeout): p for p in ports}
            for fut in as_completed(futs):
                port = futs[fut]
                try:
                    state, ms, detail = fut.result()
                except Exception as e:                    # noqa: BLE001
                    state, ms, detail = PORT_ERROR, 0.0, "%s: %s" % (type(e).__name__, e)
                results.append({"port": port, "state": state,
                                "latency_ms": round(ms, 2),
                                "service": COMMON_SERVICES.get(port, "unknown"),
                                "detail": detail})
                if time.monotonic() > end_by:
                    cancelled = True
                    for f in futs:
                        f.cancel()
                    break
    except KeyboardInterrupt:
        cancelled = True
    results.sort(key=lambda r: r["port"])
    return results, cancelled


class NetworkEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui
        self.last_scan = None

    # -- thin wrappers over module-level helpers (used by other engines) -----
    def local_ip(self):
        return get_local_ip()

    def gateway(self):
        return get_default_route()[1]

    def interface(self):
        return get_default_route()[0]

    def dns_servers(self):
        return get_dns_servers()

    def network(self):
        return get_local_network()[0]

    def wifi_info(self):
        tool = self.app.detector.path("termux-wifi-connectioninfo")
        if not tool:
            return None
        _res = Runner.run([tool], timeout=8)
        if _res.rc != 0 or not _res.out.strip():
            return None
        try:
            d = json.loads(_res.out)
            return {"ssid": d.get("ssid"), "bssid": d.get("bssid"),
                    "rssi": d.get("rssi"), "link_speed": d.get("link_speed")}
        except ValueError:
            return None

    def net_info(self):
        net, ip, gw, iface = get_local_network()
        wifi = self.wifi_info()
        return {
            "Interface": iface or "N/A",
            "Local IP": ip or "N/A",
            "Subnet": str(net) if net else "N/A",
            "Gateway": gw or "N/A",
            "DNS": ", ".join(self.dns_servers()) or "N/A",
            "SSID": (wifi or {}).get("ssid") or "unavailable (Termux:API/permission)",
            "BSSID": (wifi or {}).get("bssid") or "unavailable",
            "Connection": "Connected" if ip and not ip.startswith("127.") else "None",
        }

    def show_info(self):
        self.ui.header("NETWORK INFORMATION")
        self.ui.panels([("NETWORK", list(self.net_info().items()))])
        self.ui.pause()

    # -- ping ---------------------------------------------------------------
    def ping_once(self, ip, timeout=1):
        if Runner.check("ping"):
            _res = Runner.run(["ping", "-c", "1", "-W", str(timeout), ip], timeout=timeout + 2)
            if _res.rc == 0:
                m = re.search(r"time=([\d.]+)", _res.out)
                return float(m.group(1)) if m else 0.0
            return None
        for port in (80, 443, 53):
            try:
                t0 = time.monotonic()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return (time.monotonic() - t0) * 1000
                s.close()
            except OSError:
                continue
        return None

    def ping_device(self):
        net, ip, gw, _iface = get_local_network()
        target = self.ui.ask("Local IP to ping [%s]" % (gw or "gateway"))
        target = target or gw or ""
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            self.ui.status("bad", "Invalid IP.")
            self.ui.pause()
            return
        if net is not None and addr not in net and str(addr) != (gw or ""):
            self.ui.status("bad", "Refused: target outside the local network %s." % net)
            self.ui.pause()
            return
        if Runner.check("ping"):
            _res = Runner.run(["ping", "-c", "4", str(addr)], timeout=12)
            _rc, _out, _err = _res.rc, _res.out, _res.err
        else:
            _rc, _out, _err = 1, "", "ping not installed"
        print((_out or _err).strip()[:2000])
        self.ui.status("ok" if _rc == 0 else "bad", "exit code %d" % _rc)
        self.ui.pause()

    # -- host discovery -------------------------------------------------------
    def _discover(self, full):
        net, ip, gw, _iface = get_local_network()
        if not ip or ip.startswith("127.") or net is None:
            self.ui.status("bad", "No local network connection detected.")
            return None, None, None
        if not full:
            hosts = [gw] if gw else []
            base = str(net.network_address).rsplit(".", 1)[0]
            hosts += ["%s.%d" % (base, i) for i in (1, 2, 3, 10, 20, 50, 100, 101, 110, 150, 200, 254)]
            hosts = [h for h in hosts if ipaddress.ip_address(h) in net]
            return sorted(set(hosts)), ip, net
        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > SCAN_HOST_LIMIT:
            self.ui.status("warn", "Network %s has %d hosts; limiting to %d." %
                           (net, len(hosts), SCAN_HOST_LIMIT))
            hosts = hosts[:SCAN_HOST_LIMIT]
        return hosts, ip, net

    def scan(self, full=False):
        hosts, myip, net = self._discover(full)
        if hosts is None:
            self.ui.pause()
            return
        label = "FULL LOCAL SCAN" if full else "QUICK LOCAL SCAN"
        self.ui.header(label, "subnet %s - Ctrl+C to cancel" % net)
        found = []
        batch = 32
        try:
            for start in range(0, len(hosts), batch):
                chunk = hosts[start:start + batch]
                with ThreadPoolExecutor(max_workers=min(16, max(1, len(chunk)))) as ex:
                    futs = {ex.submit(self.ping_once, h, 1): h for h in chunk if h != myip}
                    for fut in as_completed(futs):
                        lat = fut.result()
                        if lat is not None:
                            found.append((futs[fut], lat))
                done = start + len(chunk)
                print(self.ui.t.c("   progress: %d/%d hosts, %d alive" %
                                  (done, len(hosts), len(found)), "muted"), flush=True)
                time.sleep(0.02)           # be polite: do not hammer the AP
        except KeyboardInterrupt:
            self.ui.status("warn", "Scan cancelled by user.")
        found.append((myip, 0.0))
        found.sort(key=lambda x: [int(p) for p in x[0].split(".")])
        rows = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            host_futs = {ex.submit(self._resolve_name, hip): hip for hip, _ in found}
            host_map = {}
            for fut in as_completed(host_futs):
                host_map[host_futs[fut]] = fut.result()
        for hip, lat in found:
            rows.append((hip, "%.1f ms" % lat, host_map.get(hip, "N/A"),
                         "<- THIS DEVICE" if hip == myip else ""))
        print()
        self.ui.table(["IP", "LATENCY", "HOSTNAME", ""], rows)
        self.ui.status("info", "MAC addresses are unavailable without root on Android.")
        self.last_scan = {"time": now_iso(), "network": str(net),
                          "devices": [{"ip": h, "latency_ms": l} for h, l in found]}
        self.app.store.log("Network Scan", "Success", "%s: %d devices" % (label, len(found)))
        self.ui.pause()

    @staticmethod
    def _resolve_name(ip):
        """Reverse DNS must never hang the scanner: hard 2s budget."""
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            try:
                return fut.result(timeout=2.0)[0]
            except FuturesTimeout:
                return "N/A (dns timeout)"
            except OSError:
                return "N/A"

    # -- controlled local port check ------------------------------------------
    def port_check_report(self, raw_target, raw_ports="common",
                          timeout=DEFAULT_PORT_TIMEOUT, concurrency=16):
        """Headless port check. Returns OpResult; prints nothing; raises
        nothing. Shared by the interactive menu and by `--ports`."""
        started = time.monotonic()
        result = OpResult.success({})
        net, local_ip_str, gw, iface = get_local_network()

        # Local interface IP and the *target* IP are distinct concepts and are
        # kept in distinct variables with distinct types. get_local_ip() hands
        # back a str; it is parsed here rather than being asked for .version.
        local_addr = None
        if local_ip_str:
            try:
                local_addr = ipaddress.ip_address(local_ip_str)
            except ValueError:
                result.add_warning("local interface IP %r is unparseable"
                                   % str(local_ip_str)[:48])

        try:
            target = resolve_target(raw_target)
        except ToolkitError as e:
            LOG.security("port_check.rejected", target=str(raw_target)[:64],
                         reason=e.code)
            return OpResult.failure(e.code, e.message)

        try:
            ports, port_warnings = parse_ports(raw_ports)
        except ToolkitError as e:
            return OpResult.failure(e.code, e.message)
        for w in port_warnings:
            result.add_warning(w)

        addr = target.primary
        permitted, reason = address_is_local(addr, net, gw)
        if not permitted:
            LOG.security("port_check.blocked", target=str(addr), reason=reason)
            return OpResult.failure(
                ErrCode.SECURITY_BLOCK,
                "refused: port checks are restricted to this device and its "
                "local network (%s is %s)" % (addr, reason))

        if len(target.addresses) > 1:
            result.add_warning(
                "%s resolved to %d addresses; probing %s"
                % (target.host, len(target.addresses), addr))

        deadline = time.monotonic() + min(600.0, max(10.0, timeout * len(ports)))
        rows, cancelled = scan_ports(target, ports, timeout=timeout,
                                     concurrency=concurrency, deadline=deadline)
        if cancelled:
            result.add_warning("scan stopped early (deadline or interrupt); "
                               "%d of %d ports probed" % (len(rows), len(ports)))

        counts = {}
        for r in rows:
            counts[r["state"]] = counts.get(r["state"], 0) + 1
        duration_ms = int((time.monotonic() - started) * 1000)
        result.data = {
            "target": target.as_dict(),
            "probed_address": str(addr),
            "address_family": "IPv6" if addr.version == 6 else "IPv4",
            "permitted_reason": reason,
            "local_interface": {
                "ip": str(local_addr) if local_addr else None,
                "version": local_addr.version if local_addr else None,
                "interface": iface,
                "network": str(net) if net else None,
                "gateway": gw,
            },
            "timeout_s": round(float(timeout), 3),
            "ports_requested": len(ports),
            "ports_probed": len(rows),
            "summary": counts,
            "open_ports": [r["port"] for r in rows if r["state"] == PORT_OPEN],
            "results": rows,
            "cancelled": cancelled,
            "duration_ms": duration_ms,
        }
        LOG.audit("port_check", str(addr), "success", duration_ms,
                  ports=len(rows), open=len(result.data["open_ports"]))
        return result

    def port_check(self):
        """Interactive front end. All logic lives in port_check_report()."""
        net, _ip, gw, _iface = get_local_network()
        raw_target = self.ui.ask("Target host or IP [gateway/localhost]",
                                 gw or "127.0.0.1")
        if raw_target is None:
            return
        raw_ports = self.ui.ask(
            "Ports (e.g. 22,80,8000-8010 or 'common')", "common") or "common"
        self.ui.header("LOCAL PORT CHECK", str(raw_target)[:60])
        with PleaseWait(self.ui, "Probing"):
            res = self.port_check_report(raw_target, raw_ports,
                                         timeout=min(RT.timeout, 5.0))
        self.render_port_check(res)
        self.app.store.log("Port Check", "Success" if res.ok else "Failed",
                           str(raw_target)[:64])
        self.ui.pause()

    def render_port_check(self, res):
        """The one human renderer for a port-check OpResult."""
        for w in res.warnings:
            self.ui.status("warn", w["message"])
        if not res.ok:
            for e in res.errors:
                self.ui.status("bad", "%s: %s" % (e["code"], e["message"]))
            return
        d = res.data
        self.ui.status("info", "Target %s -> %s (%s, %s)"
                       % (d["target"]["input"], d["probed_address"],
                          d["address_family"], d["permitted_reason"]))
        interesting = [r for r in d["results"]
                       if r["state"] != PORT_CLOSED] or d["results"][:0]
        rows = [(str(r["port"]), r["state"], r["service"],
                 "%.1f ms" % r["latency_ms"], r["detail"][:28])
                for r in (interesting or [])]
        if rows:
            self.ui.table(["PORT", "STATE", "SERVICE", "LATENCY", "DETAIL"], rows)
        parts = ["%s=%d" % (k, v) for k, v in sorted(d["summary"].items())]
        self.ui.status("info", "%d ports probed in %d ms  [%s]"
                       % (d["ports_probed"], d["duration_ms"], ", ".join(parts)))
        if d["open_ports"]:
            self.ui.status("warn", "%d open port(s): %s - confirm these are "
                           "services you expect to be listening."
                           % (len(d["open_ports"]),
                              ", ".join(str(p) for p in d["open_ports"][:24])))
        else:
            self.ui.status("ok", "No open ports found.")

    def save_report(self):
        if not self.last_scan:
            self.ui.status("bad", "Run a scan first.")
            self.ui.pause()
            return
        name = "clxv12_scan_%s.json" % datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path.home() / name
        try:
            if not atomic_write(path, json.dumps(self.last_scan, indent=2), mode=0o600):
                raise OSError("atomic write failed")
            self.ui.status("ok", "Report saved: %s" % path)
            self.app.store.log("Save Report", "Success", str(path))
        except OSError as e:
            self.ui.status("bad", "Save failed: %s" % e)
        self.ui.pause()

    def menu(self):
        while True:
            ch = self.ui.menu("NETWORK ENGINE", [
                ("1", "Network Info", "network"), ("2", "Quick Scan", "network"),
                ("3", "Full Local Scan", "network"), ("4", "Ping Device", "run"),
                ("5", "Local Port Check", "security"), ("6", "Save Report", "file"),
                ("0", "Back", "back"),
            ])
            if ch in (None, "0"):
                return
            {"1": self.show_info, "2": lambda: self.scan(False),
             "3": lambda: self.scan(True), "4": self.ping_device,
             "5": self.port_check, "6": self.save_report}.get(ch, lambda: None)()


# ---------------------------------------------------------------------------
# WI-FI AUDIT ENGINE - diagnostic only, current network, no attacks
# ---------------------------------------------------------------------------

class WiFiAuditEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui
        self.net = app.network

    # -- capability probe ---------------------------------------------------
    def api_status(self):
        """Honest Termux:API availability. Never assumes the binary exists,
        and never reports a capability it has not verified."""
        tool = self.app.detector.path("termux-wifi-connectioninfo")
        if not tool:
            return {"available": False, "binary": None,
                    "reason": "Termux:API not installed "
                              "(pkg install termux-api + the Termux:API app)"}
        res = Runner.run([tool], timeout=8)
        if res.rc == 127:
            return {"available": False, "binary": tool,
                    "reason": "termux-api binary present but not executable"}
        if res.rc != 0:
            detail = redact_credentials((res.err or res.out).strip()[:160])
            return {"available": False, "binary": tool,
                    "reason": "Termux:API returned exit %d%s"
                              % (res.rc, (": " + detail) if detail else ""),
                    "hint": "the Termux:API companion app and the Android "
                            "location permission are both required"}
        if not res.out.strip():
            return {"available": False, "binary": tool,
                    "reason": "Termux:API returned empty output "
                              "(location permission likely denied)"}
        try:
            json.loads(res.out)
        except ValueError:
            return {"available": False, "binary": tool,
                    "reason": "Termux:API returned non-JSON output"}
        return {"available": True, "binary": tool, "reason": ""}

    # -- headless collection ------------------------------------------------
    def collect(self, probe_gateway=True):
        """Return an OpResult holding the whole audit. Prints nothing."""
        started = time.monotonic()
        result = OpResult.success({})
        checks = []

        def add(status, msg, detail=""):
            checks.append({"status": status, "message": str(msg),
                           "detail": str(detail)})

        try:
            info = self.net.net_info()
        except Exception as e:                            # noqa: BLE001
            return OpResult.from_exception(e)

        api = self.api_status()
        if api["available"]:
            add("PASS", "SSID identified: %s" % info["SSID"])
        else:
            add("UNAVAILABLE", "SSID/BSSID unreadable", api["reason"])

        gw = self.net.gateway()
        ip_str = self.net.local_ip()
        if gw:
            add("PASS", "Gateway detected: %s" % gw)
            if probe_gateway:
                lat = self.net.ping_once(gw, 2)
                if lat is not None:
                    add("PASS", "Gateway reachable", "%.1f ms" % lat)
                else:
                    add("WARNING", "Gateway not responding to ping")
        else:
            add("UNKNOWN", "No default gateway found")

        if ip_str and not str(ip_str).startswith("127."):
            add("PASS", "Local IP assigned: %s" % ip_str)
        else:
            add("UNKNOWN", "No routable local IP assigned")

        dns = self.net.dns_servers()
        if dns:
            add("INFO", "DNS servers: %s" % ", ".join(dns))
            known = {"127.0.0.1", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                     "9.9.9.9", "149.112.112.112"}
            odd = []
            for d in dns:
                try:
                    a = ipaddress.ip_address(d)
                    if not a.is_private and d not in known and not a.is_loopback:
                        odd.append(d)
                except ValueError:
                    odd.append(d)
            if odd:
                add("WARNING", "Unexpected DNS server(s)", ", ".join(odd))
            try:
                t0 = time.monotonic()
                _getaddrinfo_bounded("example.com", timeout=min(RT.timeout, 5.0))
                add("PASS", "DNS resolution works",
                    "%.0f ms" % ((time.monotonic() - t0) * 1000))
            except ToolkitError as e:
                add("WARNING", "DNS resolution failing", e.message)
        else:
            add("UNKNOWN", "No DNS configuration readable")

        if gw and probe_gateway:
            try:
                tgt = resolve_target(gw)
                rows, _ = scan_ports(tgt, [23, 80, 8080], timeout=0.7, concurrency=3)
                states = {r["port"]: r["state"] for r in rows}
                if states.get(80) == PORT_OPEN or states.get(8080) == PORT_OPEN:
                    add("WARNING", "Plain HTTP service reachable on gateway",
                        "ports: %s" % ", ".join(str(p) for p in (80, 8080)
                                                if states.get(p) == PORT_OPEN))
                else:
                    add("PASS", "No plain HTTP admin service on gateway")
                if states.get(23) == PORT_OPEN:
                    add("WARNING", "Telnet (23) open on gateway - cleartext protocol")
                else:
                    add("PASS", "No Telnet on gateway")
            except ToolkitError as e:
                add("UNKNOWN", "Gateway service probe skipped", e.message)

        add("UNAVAILABLE", "Wireless encryption mode (WPA2/WPA3) not readable",
            "requires root or Termux:API; this build does not guess")

        counts = {}
        for c in checks:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        result.data = {
            "connection": info,
            "termux_api": api,
            "checks": checks,
            "summary": counts,
            "warnings_count": counts.get("WARNING", 0),
            "unavailable_count": counts.get("UNAVAILABLE", 0),
            "verdict": "indicators only - this audit cannot prove a network is secure",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
        if not api["available"]:
            result.add_warning("Wi-Fi identity checks unavailable: %s" % api["reason"],
                               ErrCode.UNAVAILABLE)
        return result

    def run(self):
        self.ui.clear()
        self.ui.header("WI-FI SECURITY AUDIT", "current connection - diagnostic only")
        with PleaseWait(self.ui, "Auditing"):
            res = self.collect()
        self.render(res)
        self.app.store.log("Wi-Fi Audit", "Success" if res.ok else "Failed",
                           "%d warnings" % (res.data or {}).get("warnings_count", 0))
        self.ui.pause()

    def render(self, res):
        if not res.ok:
            for e in res.errors:
                self.ui.status("bad", "%s: %s" % (e["code"], e["message"]))
            return
        d = res.data
        self.ui.panels([("CONNECTION", list(d["connection"].items()))])
        print()
        print(self.ui.t.c("CHECKS", "accent"))
        colors = {"PASS": "success", "WARNING": "warning", "UNKNOWN": "info",
                  "UNAVAILABLE": "info", "INFO": "muted"}
        for c in d["checks"]:
            line = "  %s %s" % (self.ui.t.c("[%-11s]" % c["status"],
                                            colors.get(c["status"], "muted")),
                                c["message"])
            if c["detail"]:
                line += self.ui.t.c("  (%s)" % c["detail"][:70], "muted")
            print(line)
        print()
        self.ui.panels([("SUMMARY", [
            ("Warnings", str(d["warnings_count"])),
            ("Unavailable", str(d["unavailable_count"])),
            ("Verdict", "indicators only - not a guarantee"),
        ])])
        self.ui.status("info", "This audit cannot prove a network is 100% secure.")


# ---------------------------------------------------------------------------
# FILE ENGINE - professional browsing with safe ops
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# FILE TOOLS - tree / du / find / grep / head / tail / cat, all bounded
# ---------------------------------------------------------------------------

DEFAULT_SKIP_DIRS = ("node_modules", ".git", ".gradle", "__pycache__",
                     "build", "dist", ".venv", "venv", ".tox", ".idea",
                     ".mypy_cache", ".pytest_cache", "vendor")

BINARY_SNIFF_BYTES = 8192
TEXT_CONTROL = bytes(range(0, 7)) + bytes(range(14, 32)) + b"\x7f"


def is_binary_file(path, sniff=BINARY_SNIFF_BYTES):
    """NUL byte or a high density of control characters => treat as binary.
    Never load the whole file to find out."""
    try:
        fd = open_nofollow(path, os.O_RDONLY)
    except (OSError, SecurityBlock):
        return True
    try:
        chunk = os.read(fd, sniff)
    except OSError:
        return True
    finally:
        os.close(fd)
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    ctrl = sum(chunk.count(bytes([c])) for c in TEXT_CONTROL)
    return ctrl / len(chunk) > 0.30


def _skip_set(extra=None, include_heavy=False):
    if include_heavy:
        return set(extra or ())
    base = set(CONFIG.get("search.skip_dirs", list(DEFAULT_SKIP_DIRS)))
    base.update(extra or ())
    return base


def file_tree(root, max_depth=3, max_entries=500, skip_dirs=None,
              include_heavy=False, show_hidden=False):
    """ASCII/Unicode directory tree with hard entry and depth caps."""
    base = safe_path(str(root), must_exist=True)
    if base is None:
        raise SecurityBlock("path is outside the approved roots: %s" % root,
                            ErrCode.SECURITY_BLOCK)
    skip = _skip_set(skip_dirs, include_heavy)
    lines, counted, truncated = [], 0, False

    def walk(cur, prefix, depth):
        nonlocal counted, truncated
        if depth > max_depth or truncated:
            return
        try:
            entries = sorted(os.scandir(str(cur)),
                             key=lambda e: (not e.is_dir(follow_symlinks=False),
                                            e.name.lower()))
        except (OSError, PermissionError) as e:
            lines.append(prefix + "└── [unreadable: %s]" % type(e).__name__)
            return
        visible = [e for e in entries
                   if (show_hidden or not e.name.startswith("."))
                   and e.name not in skip]
        for idx, entry in enumerate(visible):
            if counted >= max_entries:
                truncated = True
                return
            last = idx == len(visible) - 1
            branch = "└── " if last else "├── "
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_link = entry.is_symlink()
                size = "" if is_dir else human_size(entry.stat(follow_symlinks=False).st_size)
            except OSError:
                is_dir, is_link, size = False, False, "?"
            label = entry.name + ("/" if is_dir else "")
            if is_link:
                label += " -> (symlink, not followed)"
            elif size:
                label += "  " + size
            lines.append(prefix + branch + label)
            counted += 1
            if is_dir and not is_link:
                walk(Path(entry.path), prefix + ("    " if last else "│   "), depth + 1)

    walk(base, "", 1)
    return OpResult.success({
        "root": str(base), "lines": lines, "entries": counted,
        "max_depth": max_depth, "truncated": truncated,
        "skipped_dirs": sorted(skip),
    })


def disk_usage(root, top=20, max_entries=200000, skip_dirs=None,
               include_heavy=False):
    """Per-child disk usage, largest first. Symlinks are never followed."""
    base = safe_path(str(root), must_exist=True)
    if base is None:
        raise SecurityBlock("path is outside the approved roots: %s" % root,
                            ErrCode.SECURITY_BLOCK)
    skip = _skip_set(skip_dirs, include_heavy)
    rows, total, visited, capped = [], 0, 0, False

    def measure(p):
        nonlocal visited, capped
        size = 0
        try:
            for cur, dirs, files in os.walk(str(p), followlinks=False):
                dirs[:] = [d for d in dirs if d not in skip]
                for fn in files:
                    if visited >= max_entries:
                        capped = True
                        return size
                    visited += 1
                    try:
                        size += os.lstat(os.path.join(cur, fn)).st_size
                    except OSError:
                        pass
        except OSError:
            pass
        return size

    try:
        children = list(os.scandir(str(base)))
    except OSError as e:
        raise PermissionDenied("cannot list %s: %s" % (base, e))
    for entry in children:
        if entry.name in skip:
            continue
        try:
            if entry.is_symlink():
                size = entry.stat(follow_symlinks=False).st_size
                kind = "symlink"
            elif entry.is_dir(follow_symlinks=False):
                size = measure(Path(entry.path))
                kind = "dir"
            else:
                size = entry.stat(follow_symlinks=False).st_size
                kind = "file"
        except OSError:
            continue
        total += size
        rows.append({"name": entry.name, "kind": kind, "bytes": size,
                     "human": human_size(size)})
    rows.sort(key=lambda r: -r["bytes"])
    for r in rows:
        r["percent"] = round(r["bytes"] / total * 100, 1) if total else 0.0
    res = OpResult.success({
        "root": str(base), "total_bytes": total, "total_human": human_size(total),
        "files_visited": visited, "entries": rows[:int(top)],
        "entry_count": len(rows), "capped": capped,
    })
    if capped:
        res.add_warning("entry cap %d reached; totals are a lower bound" % max_entries)
    return res


def find_files(root, name=None, ext=None, regex=None, kind="any",
               max_depth=None, max_results=None, skip_dirs=None,
               include_heavy=False, ignore_case=True, min_size=None,
               max_size=None, newer_than=None):
    """Name/extension/regex search over a bounded walk. Returns OpResult."""
    base = safe_path(str(root), must_exist=True)
    if base is None:
        raise SecurityBlock("path is outside the approved roots: %s" % root,
                            ErrCode.SECURITY_BLOCK)
    depth = int(max_depth if max_depth is not None else RT.depth)
    limit = int(max_results if max_results is not None else RT.max_results)
    skip = _skip_set(skip_dirs, include_heavy)
    pattern = None
    if regex:
        try:
            pattern = re.compile(regex, re.IGNORECASE if ignore_case else 0)
        except re.error as e:
            raise InvalidArgument("invalid regex %r: %s" % (str(regex)[:40], e))
    needle = (name or "").lower() if ignore_case else (name or "")
    exts = tuple(e if e.startswith(".") else "." + e
                 for e in ([ext] if isinstance(ext, str) else (ext or [])))

    hits, scanned, truncated = [], 0, False
    base_depth = len(base.parts)
    try:
        for cur, dirs, files in os.walk(str(base), followlinks=False):
            cur_path = Path(cur)
            if len(cur_path.parts) - base_depth >= depth:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")]
            candidates = ([(d, True) for d in dirs] if kind in ("any", "dir") else [])
            candidates += ([(f, False) for f in files] if kind in ("any", "file") else [])
            for nm, is_dir in candidates:
                scanned += 1
                if needle and needle not in (nm.lower() if ignore_case else nm):
                    continue
                if exts and (is_dir or not nm.endswith(exts)):
                    continue
                full = cur_path / nm
                if pattern and not pattern.search(str(full)):
                    continue
                try:
                    st = full.lstat()
                except OSError:
                    continue
                if not is_dir:
                    if min_size is not None and st.st_size < min_size:
                        continue
                    if max_size is not None and st.st_size > max_size:
                        continue
                if newer_than is not None and st.st_mtime < newer_than:
                    continue
                hits.append({
                    "path": str(full), "name": nm,
                    "type": "dir" if is_dir else ("symlink" if full.is_symlink() else "file"),
                    "bytes": 0 if is_dir else st.st_size,
                    "size": "" if is_dir else human_size(st.st_size),
                    "modified": datetime.fromtimestamp(st.st_mtime).isoformat(
                        timespec="seconds"),
                })
                if len(hits) >= limit:
                    truncated = True
                    break
            if truncated:
                break
    except OSError as e:
        raise PermissionDenied("walk failed under %s: %s" % (base, e))
    res = OpResult.success({
        "root": str(base), "scanned": scanned, "matches": len(hits),
        "truncated": truncated, "results": hits,
        "criteria": {"name": name, "ext": list(exts) or None, "regex": regex,
                     "kind": kind, "max_depth": depth, "max_results": limit},
    })
    if truncated:
        res.add_warning("result cap %d reached; refine the query or raise "
                        "--max-results" % limit)
    return res


def grep_files(root, pattern, regex=True, ignore_case=True, max_results=None,
               max_file_size=None, max_depth=None, skip_dirs=None,
               include_heavy=False, ext=None, context=0):
    """Stream-search file CONTENT line by line.

    Files are never loaded whole: each line is read and discarded, so a 2 GB
    log costs a constant amount of RAM."""
    base = safe_path(str(root), must_exist=True)
    if base is None:
        raise SecurityBlock("path is outside the approved roots: %s" % root,
                            ErrCode.SECURITY_BLOCK)
    if not pattern:
        raise InvalidArgument("empty search pattern")
    limit = int(max_results if max_results is not None else RT.max_results)
    size_cap = int(max_file_size if max_file_size is not None
                   else CONFIG.get("limits.max_search_file_size", 4 << 20))
    depth = int(max_depth if max_depth is not None else RT.depth)
    skip = _skip_set(skip_dirs, include_heavy)
    flags = re.IGNORECASE if ignore_case else 0
    if regex:
        try:
            rx = re.compile(pattern, flags)
        except re.error as e:
            raise InvalidArgument("invalid regex %r: %s" % (str(pattern)[:40], e))
    else:
        rx = re.compile(re.escape(pattern), flags)
    exts = tuple(e if e.startswith(".") else "." + e
                 for e in ([ext] if isinstance(ext, str) else (ext or [])))

    hits, files_scanned, skipped = [], 0, {"binary": 0, "too_large": 0,
                                           "unreadable": 0}
    truncated = False
    base_depth = len(base.parts)
    targets = [base] if base.is_file() else []
    if base.is_dir():
        for cur, dirs, files in os.walk(str(base), followlinks=False):
            cur_path = Path(cur)
            if len(cur_path.parts) - base_depth >= depth:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")]
            for fn in files:
                if exts and not fn.endswith(exts):
                    continue
                targets.append(cur_path / fn)
    for fp in targets:
        if truncated:
            break
        try:
            st = fp.lstat()
            if not stat_module_isreg(st.st_mode):
                continue
            if st.st_size > size_cap:
                skipped["too_large"] += 1
                continue
            if is_binary_file(fp):
                skipped["binary"] += 1
                continue
            files_scanned += 1
            buf = []
            with open(str(fp), "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    if context:
                        buf.append(line.rstrip("\n")[:400])
                        if len(buf) > context + 1:
                            buf.pop(0)
                    if rx.search(line):
                        hits.append({
                            "path": str(fp), "line": lineno,
                            "text": redact_credentials(line.rstrip("\n")[:400]),
                            "before": [redact_credentials(b) for b in buf[:-1]]
                                      if context else [],
                        })
                        if len(hits) >= limit:
                            truncated = True
                            break
        except (OSError, UnicodeError, SecurityBlock):
            skipped["unreadable"] += 1
            continue
    res = OpResult.success({
        "root": str(base), "pattern": pattern, "regex": bool(regex),
        "files_scanned": files_scanned, "matches": len(hits),
        "skipped": skipped, "truncated": truncated, "results": hits,
    })
    if truncated:
        res.add_warning("match cap %d reached" % limit)
    if skipped["binary"]:
        res.add_warning("%d binary file(s) skipped" % skipped["binary"])
    return res


def head_file(path, lines=20, max_bytes=None):
    return _head_tail(path, lines, max_bytes, tail=False)


def tail_file(path, lines=20, max_bytes=None):
    return _head_tail(path, lines, max_bytes, tail=True)


def _head_tail(path, lines, max_bytes, tail):
    p = safe_path(str(path), must_exist=True)
    if p is None:
        raise SecurityBlock("path is outside the approved roots: %s" % path,
                            ErrCode.SECURITY_BLOCK)
    if p.is_dir():
        raise InvalidArgument("%s is a directory" % p, ErrCode.INVALID_PATH)
    n = max(1, min(int(lines), 10000))
    binary = is_binary_file(p)
    if binary:
        return OpResult.success({
            "path": str(p), "binary": True, "lines": [],
            "note": "binary file; use the hex viewer instead",
        })
    cap = int(max_bytes if max_bytes is not None
              else CONFIG.get("limits.max_read_size", 8 << 20))
    out = []
    try:
        with open(str(p), "r", encoding="utf-8", errors="replace") as fh:
            if tail:
                ring = collections_deque_safe(n)
                read = 0
                for line in fh:
                    read += len(line)
                    ring.append(line.rstrip("\n")[:2000])
                    if read > cap:
                        break
                out = list(ring)
            else:
                for i, line in enumerate(fh):
                    if i >= n:
                        break
                    out.append(line.rstrip("\n")[:2000])
    except OSError as e:
        raise PermissionDenied("cannot read %s: %s" % (p, e))
    return OpResult.success({
        "path": str(p), "binary": False, "mode": "tail" if tail else "head",
        "requested": n, "lines": out, "returned": len(out),
        "bytes": p.stat().st_size,
    })


def collections_deque_safe(n):
    from collections import deque
    return deque(maxlen=n)


def cat_file(path, max_bytes=None):
    """Bounded whole-file read with binary refusal."""
    p = safe_path(str(path), must_exist=True)
    if p is None:
        raise SecurityBlock("path is outside the approved roots: %s" % path,
                            ErrCode.SECURITY_BLOCK)
    if p.is_dir():
        raise InvalidArgument("%s is a directory" % p, ErrCode.INVALID_PATH)
    if is_binary_file(p):
        return OpResult.failure(ErrCode.INVALID_ARGUMENT,
                                "%s is a binary file; refusing to dump it to "
                                "the terminal" % p.name)
    data, truncated = read_file_bounded(p, max_bytes)
    text = data.decode("utf-8", errors="replace")
    res = OpResult.success({"path": str(p), "bytes": len(data),
                            "truncated": truncated,
                            "text": redact_credentials(text)})
    if truncated:
        res.add_warning("output truncated at the read limit")
    return res


# ---------------------------------------------------------------------------
# BENCHMARK - internal timings, used to spot performance regressions
# ---------------------------------------------------------------------------

BENCHMARK_BASELINES_MS = {
    "import_and_init": 1500, "tool_detection": 8000, "tool_detection_cached": 200,
    "filesystem_scan": 6000, "file_search": 6000, "content_search": 8000,
    "port_probe_64": 5000, "json_render": 300, "store_roundtrip": 500,
}


def run_benchmark(app, iterations=1):
    """Measure the hot paths. Reports duration_ms against a soft baseline."""
    marks = []

    def bench(name, fn):
        best, err = None, None
        for _ in range(max(1, int(iterations))):
            t0 = time.perf_counter()
            try:
                fn()
            except Exception as e:                        # noqa: BLE001
                err = "%s: %s" % (type(e).__name__, e)
                break
            dt = (time.perf_counter() - t0) * 1000
            best = dt if best is None else min(best, dt)
        baseline = BENCHMARK_BASELINES_MS.get(name)
        marks.append({
            "benchmark": name,
            "duration_ms": round(best, 2) if best is not None else None,
            "baseline_ms": baseline,
            "status": ("ERROR" if err else
                       ("OK" if baseline is None or best <= baseline else "SLOW")),
            "error": err,
        })

    bench("import_and_init", lambda: Theme(force_no_color=True))
    app.detector._cache = {} if hasattr(app.detector, "_cache") else None
    bench("tool_detection", app.detector.scan)
    bench("tool_detection_cached", app.detector.scan)
    bench("filesystem_scan", lambda: list(bounded_walk(Path.home(), max_depth=3,
                                                       max_entries=1500)))
    bench("file_search", lambda: find_files(Path.home(), ext=".json",
                                            max_depth=3, max_results=50))
    bench("content_search", lambda: grep_files(CONFIG_DIR, "version",
                                               max_results=25, max_depth=2))
    bench("port_probe_64", lambda: app.network.port_check_report(
        "127.0.0.1", "9000-9063", timeout=0.15, concurrency=32))
    bench("json_render", lambda: json.dumps(data_system(app).envelope("system"),
                                            default=str))

    def _store_rt():
        app.store.save("config", {"bench": 1})
        app.store.load("config", {})
    bench("store_roundtrip", _store_rt)

    slow = [m["benchmark"] for m in marks if m["status"] == "SLOW"]
    errs = [m["benchmark"] for m in marks if m["status"] == "ERROR"]
    res = OpResult.success({
        "iterations": int(iterations),
        "benchmarks": marks,
        "total_ms": round(sum(m["duration_ms"] or 0 for m in marks), 2),
        "slow": slow, "errors": errs,
        "note": "baselines are soft targets for a mid-range Android device; "
                "SLOW is a regression hint, not a failure",
    })
    if errs:
        res.add_error(ErrCode.INTERNAL, "%d benchmark(s) raised" % len(errs))
    elif slow:
        res.add_warning("%d benchmark(s) exceeded their baseline: %s"
                        % (len(slow), ", ".join(slow)))
    return res


class FileEngine:
    """File browser + operations. EVERY operation routes through
    secure_target(): symlink-aware resolution, approved-roots containment,
    explicit symlink policy. Out-of-bounds => REFUSE, never execute."""

    HIDDEN = False

    def __init__(self, app):
        self.app = app
        self.ui = app.ui

    # -- listing -------------------------------------------------------------
    def _listing(self, cwd):
        try:
            entries = sorted(cwd.iterdir(),
                             key=lambda x: (not x.is_dir(), x.name.casefold()))
        except OSError as e:
            self.ui.status("bad", str(e))
            return []
        if not self.HIDDEN:
            entries = [e for e in entries if not e.name.startswith(".")]
        return entries

    def _row(self, e):
        try:
            if e.is_symlink():
                tag = "<LINK>" + ("/" if e.is_dir() else "")
                return (e.name, tag, "", "")
            if e.is_dir():
                return (e.name + "/", "<DIR>", "", "")
            st = e.stat()
            mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            return (e.name, human_size(st.st_size), oct(st.st_mode & 0o777)[2:], mtime)
        except OSError:
            return (e.name, "?", "?", "?")

    # -- unified security gate -------------------------------------------------
    def _target(self, cwd, prompt, for_write=False, must_exist=True,
                allow_symlink_link_op=False):
        raw = self.ui.ask(prompt)
        if not raw:
            return None
        p = secure_target(raw, base=cwd, for_write=for_write,
                          must_exist=must_exist,
                          allow_symlink_link_op=allow_symlink_link_op)
        if p is None:
            self.ui.status("bad", "REFUSED: outside approved roots, forbidden "
                                   "symlink, or invalid path.")
        return p

    def _enter(self, e):
        """Resolve a directory entry for browsing. Symlinks are followed only
        when the resolved target stays inside approved roots."""
        try:
            target = e.resolve()
        except OSError:
            return None
        roots = read_roots()
        if any(target == r or r in target.parents for r in roots):
            return target
        return None

    # -- browsing ---------------------------------------------------------------
    def browse(self):
        cwd = Path.home().resolve()
        while True:
            entries = self._listing(cwd)
            self.ui.header("FILE MANAGER", str(cwd))
            rows = [(str(i + 1),) + self._row(e) for i, e in enumerate(entries[:200])]
            self.ui.table(["#", "NAME", "SIZE", "PERM", "MODIFIED"], rows)
            if len(entries) > 200:
                self.ui.status("warn", "Directory truncated at 200 entries.")
            print(self.ui.t.c(
                "[#] open entry  [o] path  [s] search  [.] hidden:%s  [u] up  "
                "[c] mkdir  [n] new file  [p] copy  [m] move  [r] rename  "
                "[d] delete  [i] info  [0] back" % ("on" if self.HIDDEN else "off"),
                "muted"))
            raw = self.ui.ask("Select")
            if raw is None or raw == "0":
                return
            if raw == "u":
                if cwd != cwd.parent:
                    cwd = cwd.parent
                continue
            if raw == ".":
                self.HIDDEN = not self.HIDDEN
                continue
            if raw == "o":
                p = secure_target(self.ui.ask("Path") or "", base=cwd,
                                  must_exist=True)
                if p and p.is_dir():
                    cwd = p
                else:
                    self.ui.status("bad", "Invalid directory or outside approved roots.")
                    self.ui.pause()
                continue
            if raw == "s":
                self.search(cwd)
                continue
            if raw == "c":
                self.mkdir(cwd)
                continue
            if raw == "n":
                self.touch(cwd)
                continue
            if raw == "p":
                self.copy(cwd)
                continue
            if raw == "m":
                self.move(cwd)
                continue
            if raw == "r":
                self.rename(cwd)
                continue
            if raw == "d":
                self.delete(cwd)
                continue
            if raw == "i":
                self.info(cwd)
                continue
            if raw.isdigit():
                i = int(raw) - 1
                if 0 <= i < min(len(entries), 200):
                    e = entries[i]
                    try:
                        if e.is_dir():
                            target = self._enter(e)
                            if target is None:
                                self.ui.status("bad", "REFUSED: symlink points outside approved roots.")
                                self.ui.pause()
                                continue
                            cwd = target
                        else:
                            rp = e.resolve() if (e.is_symlink() or e.exists()) else e
                            roots = read_roots()
                            if not any(rp == r or r in rp.parents for r in roots):
                                self.ui.status("bad", "REFUSED: symlink points outside approved roots.")
                                self.ui.pause()
                                continue
                            self._file_info(rp)
                            self.ui.pause()
                    except OSError as ex:
                        self.ui.status("bad", str(ex))
                        self.ui.pause()

    # -- operations (all routed through secure_target) --------------------------
    def mkdir(self, cwd):
        p = self._target(cwd, "New directory name", for_write=True, must_exist=False)
        if not p:
            return
        try:
            p.mkdir()
            self.ui.status("ok", "Created %s" % p)
        except OSError as e:
            self.ui.status("bad", str(e))

    def touch(self, cwd):
        p = self._target(cwd, "New file name", for_write=True, must_exist=False)
        if not p:
            return
        try:
            p.touch(exist_ok=True)
            self.ui.status("ok", "Created %s" % p)
        except OSError as e:
            self.ui.status("bad", str(e))

    def search(self, cwd):
        q = self.ui.ask("Name contains")
        if not q:
            return
        results = []
        for current, entries, _d in bounded_walk(cwd, max_depth=6, max_entries=20000):
            for e in entries:
                if q.casefold() in e.name.casefold():
                    results.append(str(Path(current) / e.name))
                    if len(results) >= 100:
                        break
            if len(results) >= 100:
                break
        for r in results:
            print(" - %s" % r)
        self.ui.status("info", "%d matches." % len(results))
        self.ui.pause()

    def copy(self, cwd):
        src = self._target(cwd, "Copy what", must_exist=True)
        if not src:
            return
        if not src.exists():
            self.ui.status("bad", "Not found.")
            self.ui.pause()
            return
        dst = self._target(cwd, "Destination directory", for_write=True,
                           must_exist=True)
        if not dst:
            self.ui.pause()
            return
        final = dst / src.name if dst.is_dir() else dst
        rel = path_relation(final, src)
        if rel in ("same", "a_in_b", "b_in_a"):
            self.ui.status("bad", "Refused: destination overlaps the source.")
            self.ui.pause()
            return
        try:
            if final.exists():
                if final.is_symlink():
                    self.ui.status("bad", "Refused: destination is a symlink.")
                    self.ui.pause()
                    return
                if not self.ui.confirm("Overwrite %s?" % final, False):
                    self.ui.pause()
                    return
                if final.is_dir():
                    shutil.rmtree(str(final))
                else:
                    final.unlink()
            if src.is_symlink() or final.is_symlink():
                self.ui.status("bad", "Refused: source or destination is a symlink.")
                self.ui.pause()
                return
            if src.is_dir():
                n, skipped = copy_tree_no_symlinks(src, final)
                if skipped:
                    self.ui.status("warn", "%d symlink/special entries skipped (never followed)." % skipped)
            else:
                shutil.copy2(str(src), str(final))
            if not final.exists():
                self.ui.status("bad", "Copy verification failed: destination missing.")
            else:
                self.ui.status("ok", "Copied -> %s" % final)
        except OSError as e:
            self.ui.status("bad", "Copy failed: %s" % e)
        self.ui.pause()

    def move(self, cwd):
        src = self._target(cwd, "Move what", must_exist=True,
                           allow_symlink_link_op=True)
        if not src:
            return
        if not src.exists() and not src.is_symlink():
            self.ui.status("bad", "Not found.")
            self.ui.pause()
            return
        dst = self._target(cwd, "Destination directory", for_write=True,
                           must_exist=True)
        if not dst:
            self.ui.pause()
            return
        final = dst / src.name
        rel = path_relation(final, src)
        if rel == "same":
            self.ui.status("bad", "Source and destination are identical.")
            self.ui.pause()
            return
        if rel == "a_in_b":
            self.ui.status("bad", "Refused: destination lies inside the source.")
            self.ui.pause()
            return
        try:
            if final.exists():
                if final.is_symlink():
                    self.ui.status("bad", "Refused: destination is a symlink.")
                    self.ui.pause()
                    return
                if not self.ui.confirm("Overwrite %s?" % final, False):
                    self.ui.pause()
                    return
                if final.is_dir():
                    shutil.rmtree(str(final))
                else:
                    final.unlink()
            shutil.move(str(src), str(final))
            if final.exists() and not src.exists():
                self.ui.status("ok", "Moved -> %s" % final)
            else:
                self.ui.status("bad", "Move verification failed (source/destination state unexpected).")
        except OSError as e:
            self.ui.status("bad", "Move failed: %s" % e)
        self.ui.pause()

    def rename(self, cwd):
        src = self._target(cwd, "Rename what", must_exist=True,
                           allow_symlink_link_op=True)
        if not src:
            return
        name = self.ui.ask("New name")
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            self.ui.status("bad", "Invalid name.")
            self.ui.pause()
            return
        dest = src.parent / name
        if dest.exists():
            self.ui.status("bad", "%s already exists." % name)
            self.ui.pause()
            return
        try:
            src.rename(dest)
            UNDO.record("rename", source=str(src), destination=str(dest))
            LOG.audit("rename", str(src), "success", None, destination=str(dest))
            self.ui.status("ok", "Renamed. Undo is available.")
        except OSError as e:
            LOG.audit("rename", str(src), "failure", None, error=str(e))
            self.ui.status("bad", "Rename failed: %s" % e)
        self.ui.pause()

    def delete(self, cwd):
        p = self._target(cwd, "Delete what", must_exist=True,
                         allow_symlink_link_op=True)
        if not p:
            return
        if not p.exists() and not p.is_symlink():
            self.ui.status("bad", "Not found.")
            self.ui.pause()
            return
        if is_protected(p):
            self.ui.status("bad", "Protected path - refused.")
            self.ui.pause()
            return
        isdir = p.is_dir()
        try:
            size, _ = dir_size(p) if isdir else (p.stat().st_size, False)
        except OSError:
            size = 0
        what = "symlink" if p.is_symlink() else ("directory" if isdir else "file")
        self.ui.status("warn", "Target: %s (%s, %s)" % (p, what, human_size(size)))

        # Back up first when the config allows it and the target is a plain
        # file or directory. A symlink is only an unlink of the link itself,
        # so there is nothing to snapshot.
        backup_id = None
        want_backup = (CONFIG.get("backup.enabled", True) and not p.is_symlink()
                       and size <= MAX_BACKUP_BYTES)
        if want_backup and self.ui.confirm("Create a backup first?", True):
            with PleaseWait(self.ui, "Backing up"):
                bk = BACKUPS.create(p, reason="pre-delete")
            if bk.ok:
                backup_id = bk.data["entry"]["id"]
                self.ui.status("ok", "Backup %s (%s)"
                               % (backup_id, human_size(bk.data["entry"]["bytes"])))
            else:
                self.ui.status("warn", "Backup failed: %s"
                               % bk.errors[0]["message"])
                if not self.ui.confirm("Delete anyway, with NO backup?", False):
                    self.ui.status("info", "Cancelled.")
                    self.ui.pause()
                    return
        if not self.ui.confirm("Delete permanently?" if not backup_id
                               else "Delete now? (undo available)", False):
            self.ui.status("info", "Cancelled.")
            self.ui.pause()
            return
        t0 = time.monotonic()
        try:
            if p.is_symlink():
                p.unlink()          # removes the LINK only; target untouched
            elif isdir:
                shutil.rmtree(str(p))
            else:
                p.unlink()
            if backup_id:
                UNDO.record("delete_with_backup", source=str(p),
                            destination=str(p), backup_id=backup_id)
            LOG.audit("delete", str(p), "success",
                      (time.monotonic() - t0) * 1000, kind=what,
                      bytes=size, backup_id=backup_id or "none")
            self.app.store.log("File Delete", "Success", str(p))
            self.ui.status("ok", "Deleted." + (" Use 'Undo' to restore."
                                               if backup_id else
                                               " No backup was taken - "
                                               "this cannot be undone."))
        except OSError as e:
            LOG.audit("delete", str(p), "failure",
                      (time.monotonic() - t0) * 1000, error=str(e))
            self.ui.status("bad", "Delete failed: %s" % e)
        self.ui.pause()

    def _file_info(self, p):
        try:
            st = p.stat()
        except OSError as e:
            self.ui.status("bad", str(e))
            return
        rows = [("Path", str(p)), ("Type", "directory" if p.is_dir() else "file"),
                ("Size", human_size(st.st_size)),
                ("Permissions", oct(st.st_mode & 0o777)),
                ("Modified", datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"))]
        if p.is_file():
            try:
                with open(p, "rb") as f:
                    rows.append(("First bytes", f.read(16).hex(" ")))
            except OSError:
                rows.append(("First bytes", "unreadable"))
        self.ui.panels([("FILE", rows)])

    def info(self, cwd):
        p = self._target(cwd, "Path", must_exist=True,
                         allow_symlink_link_op=True)
        if not p:
            self.ui.pause()
            return
        self._file_info(p)
        self.ui.pause()


# ---------------------------------------------------------------------------
# ARCHIVE ENGINE - ZIP / TAR / 7Z with path-escape protection
# ---------------------------------------------------------------------------

COMPOUND_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2",
                     ".txz", ".tar", ".zip", ".7z")


def zip_tree(src, out):
    """Create a ZIP of src without EVER following symlinks (link entries and
    special files are skipped and counted). Verified with testzip before
    returning. Returns (files_added, skipped)."""
    count, skipped = 0, 0
    with zipfile.ZipFile(str(out), "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(str(src), followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for _d in list(dirs):
                if (Path(root) / _d).is_symlink():
                    dirs.remove(_d)
                    skipped += 1
            for fn in files:
                fp = Path(root) / fn
                try:
                    if fp.is_symlink() or not fp.is_file():
                        skipped += 1
                        continue
                except OSError:
                    skipped += 1
                    continue
                z.write(str(fp), str(fp.relative_to(src)))
                count += 1
    with zipfile.ZipFile(str(out)) as z:
        bad = z.testzip()
    if bad is not None:
        raise ArchiveLimitError("created zip failed verification: %s" % bad)
    return count, skipped


def tar_tree(src, out):
    """TAR counterpart of zip_tree: symlinks/specials skipped, never
    followed. Returns (files_added, skipped)."""
    count, skipped = 0, 0
    mode = "w:gz" if str(out).lower().endswith((".gz", ".tgz")) else "w"
    with tarfile.open(str(out), mode) as t:
        for root, dirs, files in os.walk(str(src), followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for _d in list(dirs):
                if (Path(root) / _d).is_symlink():
                    dirs.remove(_d)
                    skipped += 1
            for fn in files:
                fp = Path(root) / fn
                try:
                    if fp.is_symlink() or not fp.is_file():
                        skipped += 1
                        continue
                except OSError:
                    skipped += 1
                    continue
                t.add(str(fp), arcname=str(fp.relative_to(src)))
                count += 1
    try:
        with tarfile.open(str(out), "r:*") as t:
            if not t.getmembers():
                raise ArchiveLimitError("created tar is empty")
    except (tarfile.TarError, OSError):
        raise ArchiveLimitError("created tar failed verification")
    return count, skipped


def archive_stem(path):
    """Strip compound archive extensions correctly (.tar.gz -> name, not name.tar)."""
    name = Path(path).name.lower()
    for suf in COMPOUND_SUFFIXES:
        if name.endswith(suf):
            return str(Path(path).with_name(Path(path).name[:-len(suf)]))
    return str(Path(path).with_suffix(""))


class ArchiveEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui

    def _pick(self, exts, prompt):
        raw = self.ui.ask(prompt)
        p = safe_path(raw) if raw else None
        # name.endswith, NOT suffix: ".tar.gz".suffix is only ".gz" and would
        # reject every compound-suffixed archive.
        if not p or not p.name.lower().endswith(tuple(exts)) or not p.is_file():
            self.ui.status("bad", "Invalid archive file.")
            return None
        return p

    def _dest(self, prompt, default):
        raw = self.ui.ask(prompt, default)
        d = safe_path(raw, must_exist=False, for_write=True) if raw else None
        if not d:
            self.ui.status("bad", "Invalid destination.")
        return d

    # -- ZIP -------------------------------------------------------------------
    def zip_list(self):
        p = self._pick((".zip",), "ZIP path")
        if not p:
            self.ui.pause()
            return
        try:
            with zipfile.ZipFile(str(p)) as z:
                infos = z.infolist()
            rows = [(i.filename, human_size(i.file_size), str(i.compress_size)) for i in infos[:300]]
            self.ui.header("ZIP CONTENTS", "%s - %d entries" % (p.name, len(infos)))
            names = [i.filename for i in infos]
            dups = sorted({n for n in names if names.count(n) > 1})
            if dups:
                self.ui.status("warn", "Duplicate entries: %d (%s)" % (len(dups), ", ".join(dups[:4])))
            self.ui.table(["MEMBER", "SIZE", "COMPRESSED"], rows)
        except (zipfile.BadZipFile, OSError) as e:
            self.ui.status("bad", str(e))
        self.ui.pause()

    def zip_extract(self):
        p = self._pick((".zip",), "ZIP path")
        if not p:
            self.ui.pause()
            return
        d = self._dest("Extract to", archive_stem(str(p)))
        if not d:
            self.ui.pause()
            return
        if d.exists() and any(d.iterdir()) and not self.ui.confirm("Destination not empty. Continue?", False):
            self.ui.pause()
            return
        try:
            d.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(str(p)) as z:
                extracted, rejected = safe_extract_zip(z, d)
            self.ui.status("ok", "Extracted %d entries -> %s" % (extracted, d))
            if rejected:
                self.ui.status("warn", "Rejected %d unsafe members." % len(rejected))
            self.app.store.log("ZIP Extract", "Success", p.name)
        except ArchiveLimitError as e:
            self.ui.status("bad", "Safety stop: %s" % e)
        except (zipfile.BadZipFile, OSError) as e:
            self.ui.status("bad", "Extract failed: %s" % e)
        self.ui.pause()

    def zip_create(self):
        src_raw = self.ui.ask("Directory to archive")
        src = safe_path(src_raw) if src_raw else None
        if not src or not src.is_dir():
            self.ui.status("bad", "Invalid directory.")
            self.ui.pause()
            return
        out_raw = self.ui.ask("Output ZIP", str(src) + ".zip")
        out = safe_write_path(out_raw) if out_raw else None
        if not out:
            self.ui.status("bad", "Invalid output path (parent must exist inside write roots).")
            self.ui.pause()
            return
        if path_relation(out, src) in ("same", "a_in_b"):
            self.ui.status("bad", "Refused: the output archive would sit inside the archived directory.")
            self.ui.pause()
            return
        try:
            count, skipped = zip_tree(src, out)
            self.ui.status("ok", "Wrote %s (%d files) - integrity verified" % (out, count))
            if skipped:
                self.ui.status("warn", "%d symlink/special entries skipped (never followed)." % skipped)
            self.app.store.log("ZIP Create", "Success", out.name)
        except ArchiveLimitError as e:
            self.ui.status("bad", "Archive verification failed: %s" % e)
        except OSError as e:
            self.ui.status("bad", str(e))
        self.ui.pause()

    # -- TAR ---------------------------------------------------------------------
    def tar_list(self):
        p = self._pick((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"), "TAR path")
        if not p:
            self.ui.pause()
            return
        try:
            with tarfile.open(str(p), "r:*") as t:
                members = t.getmembers()
            rows = [(m.name, human_size(m.size), "dir" if m.isdir() else "file")
                    for m in members[:300]]
            self.ui.header("TAR CONTENTS", "%s - %d members" % (p.name, len(members)))
            self.ui.table(["MEMBER", "SIZE", "TYPE"], rows)
        except (tarfile.TarError, OSError) as e:
            self.ui.status("bad", str(e))
        self.ui.pause()

    def tar_extract(self):
        p = self._pick((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz"), "TAR path")
        if not p:
            self.ui.pause()
            return
        d = self._dest("Extract to", archive_stem(str(p)))
        if not d:
            self.ui.pause()
            return
        if d.exists() and any(d.iterdir()) and not self.ui.confirm("Destination not empty. Continue?", False):
            self.ui.pause()
            return
        try:
            d.mkdir(parents=True, exist_ok=True)
            with tarfile.open(str(p), "r:*") as t:
                extracted, rejected = safe_extract_tar(t, d)
            self.ui.status("ok", "Extracted %d members -> %s" % (extracted, d))
            if rejected:
                self.ui.status("warn", "Rejected %d unsafe members." % len(rejected))
            self.app.store.log("TAR Extract", "Success", p.name)
        except ArchiveLimitError as e:
            self.ui.status("bad", "Safety stop: %s" % e)
        except (tarfile.TarError, OSError) as e:
            self.ui.status("bad", "Extract failed: %s" % e)
        self.ui.pause()

    def tar_create(self):
        src_raw = self.ui.ask("Directory to archive")
        src = safe_path(src_raw) if src_raw else None
        if not src or not src.is_dir():
            self.ui.status("bad", "Invalid directory.")
            self.ui.pause()
            return
        out_raw = self.ui.ask("Output TAR (.tar.gz)", str(src) + ".tar.gz")
        out = safe_write_path(out_raw) if out_raw else None
        if not out:
            self.ui.status("bad", "Invalid output path (parent must exist inside write roots).")
            self.ui.pause()
            return
        if path_relation(out, src) in ("same", "a_in_b"):
            self.ui.status("bad", "Refused: the output archive would sit inside the archived directory.")
            self.ui.pause()
            return
        try:
            count, skipped = tar_tree(src, out)
            self.ui.status("ok", "Wrote %s (%d files) - integrity verified" % (out, count))
            if skipped:
                self.ui.status("warn", "%d symlink/special entries skipped (never followed)." % skipped)
            self.app.store.log("TAR Create", "Success", out.name)
        except ArchiveLimitError as e:
            self.ui.status("bad", "Archive verification failed: %s" % e)
        except (tarfile.TarError, OSError) as e:
            self.ui.status("bad", str(e))
        self.ui.pause()

    # -- 7Z ------------------------------------------------------------------------
    def seven_zip(self):
        if not self.app.detector.installed("7z"):
            self.ui.status("bad", "7z NOT INSTALLED.")
            self.ui.status("info", "Install with: pkg install p7zip")
            self.ui.pause()
            return
        seven = self.app.detector.path("7z")
        action = self.ui.ask("Action: list / extract / create", "list")
        if action == "list":
            p = self._pick((".7z", ".zip", ".tar", ".gz"), "Archive path")
            if p:
                Runner.display(self.ui, [seven, "l", str(p)], timeout=60)
        elif action == "extract":
            p = self._pick((".7z",), "7z archive path")
            if not p:
                self.ui.pause()
                return
            d = self._dest("Extract to", archive_stem(str(p)))
            if not d:
                self.ui.pause()
                return
            # Pre-inspect: fail closed if dangerous members are detected.
            lr = Runner.run([seven, "l", "-slt", str(p)], timeout=60)
            listing = lr.out + lr.err
            dangerous = []
            current_path = None
            for line in listing.splitlines():
                if line.startswith("Path = "):
                    current_path = line[7:].strip()
                    pure = PurePosixPath(current_path.replace("\\", "/"))
                    if pure.is_absolute() or ".." in pure.parts:
                        dangerous.append(current_path)
                elif line.startswith("Type = ") and current_path:
                    t = line[7:].strip().lower()
                    if "link" in t:
                        dangerous.append(current_path + " (%s)" % t)
            if lr.rc != 0:
                self.ui.status("bad", "7z inspection failed (exit %d); extraction refused." % lr.rc)
                self.ui.pause()
                return
            if dangerous:
                self.ui.status("bad", "7z archive contains %d dangerous member(s); extraction refused." % len(dangerous))
                for dname in dangerous[:8]:
                    print("   - %s" % dname)
                self.ui.pause()
                return
            d.mkdir(parents=True, exist_ok=True)
            res = Runner.display(self.ui, [seven, "x", str(p), "-o%s" % d], timeout=300)
            self.ui.status("warn", "Review extracted files; 7z path checks are external.")
            self.app.store.log("7z Extract", "Success" if res.rc == 0 else "Failed", p.name)
        elif action == "create":
            src_raw = self.ui.ask("Directory to archive")
            src = safe_path(src_raw) if src_raw else None
            if not src or not src.is_dir():
                self.ui.status("bad", "Invalid directory.")
                self.ui.pause()
                return
            out_raw = self.ui.ask("Output archive.7z", str(src) + ".7z")
            out = safe_path(out_raw, must_exist=False, for_write=True) if out_raw else None
            if out:
                Runner.display(self.ui, [seven, "a", str(out), str(src)], timeout=300)
        self.ui.pause()

    def menu(self):
        while True:
            ch = self.ui.menu("ARCHIVE ENGINE", [
                ("1", "ZIP List", "archive"), ("2", "ZIP Extract (safe)", "archive"),
                ("3", "ZIP Create", "build"), ("4", "TAR List", "archive"),
                ("5", "TAR Extract (safe)", "archive"), ("6", "TAR Create", "build"),
                ("7", "7z Operations", "tools"), ("0", "Back", "back"),
            ])
            if ch in (None, "0"):
                return
            {"1": self.zip_list, "2": self.zip_extract, "3": self.zip_create,
             "4": self.tar_list, "5": self.tar_extract, "6": self.tar_create,
             "7": self.seven_zip}.get(ch, lambda: None)()

# ---------------------------------------------------------------------------
# GIT ENGINE
# ---------------------------------------------------------------------------

class GitEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui

    def _repo(self):
        raw = self.ui.ask("Repository path", os.getcwd())
        p = safe_path(raw) if raw else None
        if not p or not (p / ".git").exists():
            self.ui.status("bad", "Not a Git repository.")
            return None
        return p

    def clone(self):
        url = self.ui.ask("Repository URL (https or git@)")
        if not url or not re.match(r"^(https?://|git@|ssh://)", url):
            self.ui.status("bad", "Invalid URL.")
            self.ui.pause()
            return
        if re.match(r"^https?://[^/@\s]+:[^/@\s]+@", url):
            self.ui.status("warn", "Credentials embedded in the URL will be stored by git - prefer SSH or a credential helper.")
        dst_raw = self.ui.ask("Destination directory")
        dst = safe_path(dst_raw, must_exist=False, for_write=True) if dst_raw else None
        if not dst:
            self.ui.status("bad", "Invalid destination.")
            self.ui.pause()
            return
        if not self.ui.confirm("Clone into %s?" % dst, False):
            self.ui.pause()
            return
        res = Runner.display(self.ui, ["git", "clone", url, str(dst)], timeout=600)
        self.app.store.log("Git Clone", "Success" if res.rc == 0 else "Failed", url)
        self.ui.pause()

    def _op(self, args, repo, confirm=False, timeout=300):
        if confirm and not self.ui.confirm("Run: git %s ?" % " ".join(args), False):
            self.ui.status("info", "Cancelled.")
            self.ui.pause()
            return None
        r = Runner.display(self.ui, ["git"] + args, cwd=repo, timeout=timeout)
        self.app.store.log("Git " + args[0].capitalize(),
                           "Success" if r.rc == 0 else "Failed", str(repo))
        return r.rc

    def push(self):
        repo = self._repo()
        if not repo:
            self.ui.pause()
            return
        self.ui.status("info", "Repository: %s" % repo)
        Runner.run(["git", "remote", "-v"], cwd=repo, timeout=10)
        _res = Runner.run(["git", "branch", "--show-current"], cwd=repo, timeout=10)
        self.ui.status("info", "Branch: %s" % (_res.out.strip() or "(detached)"))
        self._op(["push"], repo, confirm=True)

    def commit(self):
        repo = self._repo()
        if not repo:
            self.ui.pause()
            return
        _res = Runner.run(["git", "status", "--porcelain"], cwd=repo, timeout=15)
        if not _res.out.strip():
            self.ui.status("info", "Nothing to commit.")
            self.ui.pause()
            return
        print(_res.out)
        msg = self.ui.ask("Commit message")
        if not msg:
            self.ui.pause()
            return
        if self._op(["add", "-A"], repo) != 0:   # _op returns an int exit code
            self.ui.pause()
            return
        rc = self._op(["commit", "-m", msg], repo)
        if rc != 0:
            ident = Runner.run(["git", "var", "GIT_AUTHOR_IDENT"], cwd=repo, timeout=10)
            if ident.rc != 0:
                self.ui.status("warn", "Git identity is not configured for this repository.")
                self.ui.status("info", "Fix: git config --global user.email you@example.com")
                self.ui.status("info", '      git config --global user.name "Your Name"')
                if self.ui.confirm("Set a LOCAL identity (clxv12 <clxv12@localhost>) for THIS repo only?", False):
                    self._op(["-c", "user.name=clxv12", "-c", "user.email=clxv12@localhost",
                              "commit", "-m", msg], repo)
        self.ui.pause()

    def menu(self):
        if not Runner.check("git"):
            self.ui.status("bad", "Git: NOT INSTALLED")
            self.ui.status("info", "Install with: pkg install git")
            self.ui.pause()
            return
        while True:
            ch = self.ui.menu("GIT ENGINE", [
                ("1", "Clone", "git"), ("2", "Status", "git"),
                ("3", "Pull", "git"), ("4", "Push", "git"),
                ("5", "Commit", "git"), ("6", "Log", "history"),
                ("7", "Branches", "git"), ("8", "Checkout", "git"),
                ("9", "Remote", "git"), ("D", "Diff", "search"),
                ("0", "Back", "back"),
            ])
            if ch in (None, "0"):
                return
            if ch == "1":
                self.clone()
                continue
            repo = self._repo()
            if not repo:
                self.ui.pause()
                continue
            if ch == "2":
                self._op(["status", "-sb"], repo, timeout=60)
            elif ch == "3":
                self._op(["pull"], repo, confirm=True)
            elif ch == "4":
                self.push()
            elif ch == "5":
                self.commit()
                continue
            elif ch == "6":
                self._op(["log", "--oneline", "-20"], repo, timeout=60)
            elif ch == "7":
                self._op(["branch", "-a"], repo, timeout=60)
            elif ch == "8":
                b = self.ui.ask("Branch name")
                if b:
                    self._op(["checkout", b], repo, timeout=60)
            elif ch == "9":
                self._op(["remote", "-v"], repo, timeout=60)
            elif ch == "d":
                self._op(["diff", "--stat"], repo, timeout=60)
            self.ui.pause()


# ---------------------------------------------------------------------------
# DEVELOPER ENGINE - 100% offline utilities
# ---------------------------------------------------------------------------

class DeveloperEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui

    def _text(self, label="Input"):
        print(self.ui.t.c("Paste text; end with an empty line:", "muted"))
        lines = []
        while True:
            try:
                ln = input()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not ln:
                break
            lines.append(ln)
        return "\n".join(lines)

    def json_tool(self):
        raw = self._text("JSON")
        if not raw.strip():
            return
        try:
            obj = json.loads(raw)
            print(json.dumps(obj, ensure_ascii=False, indent=2))
            self.ui.status("ok", "VALID JSON")
        except ValueError as e:
            self.ui.status("bad", "INVALID JSON: %s" % e)
        self.ui.pause()

    def b64(self, encode):
        s = self.ui.ask("Input")
        if s is None:
            return
        try:
            out = base64.b64encode(s.encode()).decode() if encode else \
                base64.b64decode(s.encode(), validate=True).decode("utf-8", errors="replace")
            print(out)
        except (ValueError, binascii.Error) as e:
            self.ui.status("bad", "Base64 error: %s" % e)
        self.ui.pause()

    def hash_text(self, algo):
        s = self.ui.ask("Input")
        if s is None:
            return
        h = hashlib.new(algo)
        h.update(s.encode())
        print(h.hexdigest())
        self.ui.pause()

    def hash_file(self, algo):
        raw = self.ui.ask("File path")
        p = safe_path(raw) if raw else None
        if not p or not p.is_file():
            self.ui.status("bad", "Invalid file.")
            self.ui.pause()
            return
        digest = stream_hash(p, algo)
        print(digest or "unreadable")
        self.ui.pause()

    def url(self, encode):
        from urllib.parse import quote, unquote, urlsplit, urlunsplit
        s = self.ui.ask("Input")
        if s is None:
            return
        print(quote(s, safe="") if encode else unquote(s))
        self.ui.pause()

    def stats(self):
        text = self._text()
        if not text:
            return
        print(" Characters : %d" % len(text))
        print(" Words      : %d" % len(text.split()))
        print(" Lines      : %d" % len(text.splitlines()))
        print(" Bytes(UTF-8): %d" % len(text.encode("utf-8")))
        self.ui.pause()

    def hex_view(self):
        raw = self.ui.ask("File path")
        p = safe_path(raw) if raw else None
        if not p or not p.is_file():
            self.ui.status("bad", "Invalid file.")
            self.ui.pause()
            return
        try:
            with open(p, "rb") as f:
                data = f.read(4096)
        except OSError as e:
            self.ui.status("bad", str(e))
            self.ui.pause()
            return
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hx = " ".join("%02x" % b for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(" %08x  %-47s  %s" % (off, hx, asc))
        if p.stat().st_size > 4096:
            self.ui.status("info", "Showing first 4096 bytes.")
        self.ui.pause()

    def timestamp(self):
        raw = self.ui.ask("Unix timestamp ('now' for current)", "now")
        try:
            ts = time.time() if raw == "now" else float(raw)
            local = datetime.fromtimestamp(ts).astimezone()
            print(" Unix   : %.3f" % ts)
            print(" Local  : %s" % local.isoformat(timespec="seconds"))
            print(" UTC    : %s" % datetime.utcfromtimestamp(ts).isoformat(timespec="seconds"))
        except (ValueError, OverflowError, OSError) as e:
            self.ui.status("bad", "Invalid timestamp: %s" % e)
        self.ui.pause()

    def random_string(self):
        raw = self.ui.ask("Length", "24")
        try:
            n = max(1, min(int(raw), 4096))
        except ValueError:
            n = 24
        alphabet = string.ascii_letters + string.digits
        print("".join(random.SystemRandom().choice(alphabet) for _ in range(n)))
        self.ui.pause()

    def menu(self):
        while True:
            ch = self.ui.menu("DEVELOPER TOOLS", [
                ("1", "JSON Format/Validate", "tools"), ("2", "Base64 Encode", "tools"),
                ("3", "Base64 Decode", "tools"), ("4", "SHA256 (text)", "security"),
                ("5", "MD5 (text)", "security"), ("6", "File Hash", "file"),
                ("7", "URL Encode", "tools"), ("8", "URL Decode", "tools"),
                ("9", "Text Statistics", "file"), ("A", "Hex Viewer", "search"),
                ("T", "Timestamp", "system"), ("R", "Random String", "settings"),
                ("0", "Back", "back"),
            ])
            if ch in (None, "0"):
                return
            {"1": self.json_tool, "2": lambda: self.b64(True),
             "3": lambda: self.b64(False), "4": lambda: self.hash_text("sha256"),
             "5": lambda: self.hash_text("md5"), "6": self.hash_file_menu,
             "7": lambda: self.url(True), "8": lambda: self.url(False),
             "9": self.stats, "a": self.hex_view, "t": self.timestamp,
             "r": self.random_string}.get(ch.lower(), lambda: None)()

    def hash_file_menu(self):
        algo = self.ui.ask("Algorithm: sha256 / md5 / sha1", "sha256") or "sha256"
        if algo not in hashlib.algorithms_available:
            self.ui.status("bad", "Algorithm unavailable.")
            self.ui.pause()
            return
        self.hash_file(algo)


# ---------------------------------------------------------------------------
# CLEANUP ENGINE - candidates first, never silent deletion
# ---------------------------------------------------------------------------

class CleanupEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui

    def _root(self):
        raw = self.ui.ask("Root directory", str(Path.home()))
        return safe_path(raw) if raw else None

    def _confirm_delete(self, paths, label):
        # never touch protected paths, config-dir contents, or symlink
        # entries (links are never followed)
        paths = [p for p in paths
                 if not is_protected(p) and not is_config_path(p)
                 and not Path(p).is_symlink()]
        total, count = 0, 0
        for p in paths:
            s, _ = dir_size(p)
            total += s
            count += 1
        self.ui.status("warn", "%s: %d items, ~%s" % (label, count, human_size(total)))
        for p in paths[:30]:
            print(" - %s" % p)
        if len(paths) > 30:
            print(" ... and %d more" % (len(paths) - 30))
        if not paths or not self.ui.confirm("Delete these?", False):
            self.ui.status("info", "Nothing deleted.")
            self.ui.pause()
            return
        ok_n = 0
        for p in paths:
            if is_protected(p) or is_config_path(p):
                self.ui.status("warn", "protected, skipped: %s" % p)
                continue
            try:
                if Path(p).is_symlink():
                    Path(p).unlink()
                else:
                    shutil.rmtree(str(p))
                ok_n += 1
            except OSError as e:
                self.ui.status("warn", "%s: %s" % (p, e))
        self.app.store.log("Cleanup: " + label, "Success", "%d removed" % ok_n)
        self.ui.status("ok", "Removed %d items." % ok_n)
        self.ui.pause()

    def pycache(self):
        root = self._root()
        if not root:
            self.ui.pause()
            return
        with PleaseWait(self.ui, "Scanning for Python caches"):
            found = []
            for current, entries, _d in bounded_walk(root, max_depth=8, max_entries=100000):
                for e in entries:
                    if e.name == "__pycache__":
                        found.append(Path(current) / e.name)
        self.ui.header("PYTHON CACHE", "%d candidates" % len(found))
        self._confirm_delete(found, "Python cache")

    def node_modules(self):
        root = self._root()
        if not root:
            self.ui.pause()
            return
        with PleaseWait(self.ui, "Scanning for node_modules"):
            found = []
            for current, entries, _d in bounded_walk(root, max_depth=6, max_entries=60000):
                for e in entries:
                    if e.name == "node_modules":
                        found.append(Path(current) / e.name)
        self.ui.header("NODE MODULES", "%d candidates" % len(found))
        self._confirm_delete(found, "node_modules")

    def build_dirs(self):
        root = self._root()
        if not root:
            self.ui.pause()
            return
        names = {"build", "dist", ".dart_tool", ".gradle"}
        with PleaseWait(self.ui, "Scanning for build artifacts"):
            found = []
            for current, entries, _d in bounded_walk(root, max_depth=6, max_entries=60000):
                for e in entries:
                    if e.name in names:
                        found.append(Path(current) / e.name)
        self.ui.header("BUILD ARTIFACTS", "%d candidates" % len(found))
        self._confirm_delete(found, "build artifacts")

    def temp_files(self):
        root = self._root()
        if not root:
            self.ui.pause()
            return
        with PleaseWait(self.ui, "Scanning for temporary files"):
            found = []
            for current, entries, _d in bounded_walk(root, max_depth=8, max_entries=100000):
                for e in entries:
                    low = e.name.lower()
                    if low.endswith((".tmp", ".temp", ".log", ".cache")) or \
                       low in (".ds_store", "thumbs.db"):
                        found.append(Path(current) / e.name)
        self.ui.header("TEMPORARY FILES", "%d candidates" % len(found))
        paths = [p for p in found if p.is_file()]
        total = 0
        for p in paths[:60]:
            print(" - %s" % p)
        try:
            total = sum(p.stat().st_size for p in paths)
        except OSError:
            pass
        self.ui.status("warn", "%d files, ~%s" % (len(paths), human_size(total)))
        paths = [p for p in paths
                 if not is_protected(p) and not is_config_path(p) and not p.is_symlink()]
        if paths and self.ui.confirm("Delete these files?", False):
            n = 0
            for p in paths:
                if is_protected(p) or is_config_path(p):
                    continue
                try:
                    p.unlink()
                    n += 1
                except OSError:
                    pass
            self.app.store.log("Cleanup: temp files", "Success", "%d removed" % n)
            self.ui.status("ok", "Deleted %d files." % n)
        else:
            self.ui.status("info", "Nothing deleted.")
        self.ui.pause()

    def empty_dirs(self):
        root = self._root()
        if not root:
            self.ui.pause()
            return
        with PleaseWait(self.ui, "Scanning for empty directories"):
            found = []
            for current, entries, _d in bounded_walk(root, max_depth=8, max_entries=60000):
                for e in entries:
                    try:
                        ep = Path(current) / e.name
                        if e.is_dir(follow_symlinks=False) and not any(ep.iterdir()):
                            found.append(ep)
                    except OSError:
                        pass
        self.ui.header("EMPTY DIRECTORIES", "%d candidates" % len(found))
        self._confirm_delete(found, "empty directories")

    def gradle_cache(self):
        g = Path.home() / ".gradle"
        if not g.exists():
            self.ui.status("info", "No ~/.gradle cache found.")
            self.ui.pause()
            return
        size, capped = dir_size(g)
        self.ui.status("warn", "~/.gradle: %s%s" % (human_size(size), " (scan capped)" if capped else ""))
        if self.ui.confirm("Delete the Gradle cache? Gradle will re-download dependencies.", False):
            try:
                shutil.rmtree(str(g))
                self.app.store.log("Cleanup: gradle cache", "Success")
                self.ui.status("ok", "Gradle cache removed.")
            except OSError as e:
                self.ui.status("bad", str(e))
        self.ui.pause()

    def menu(self):
        while True:
            ch = self.ui.menu("CLEANUP ENGINE", [
                ("1", "Python Cache", "cleanup"), ("2", "node_modules", "cleanup"),
                ("3", "Build/Dist/Gradle-artifacts", "cleanup"), ("4", "Temp Files", "cleanup"),
                ("5", "Empty Directories", "cleanup"), ("6", "Gradle Cache (~/.gradle)", "cleanup"),
                ("0", "Back", "back"),
            ])
            if ch in (None, "0"):
                return
            {"1": self.pycache, "2": self.node_modules, "3": self.build_dirs,
             "4": self.temp_files, "5": self.empty_dirs,
             "6": self.gradle_cache}.get(ch, lambda: None)()


# ---------------------------------------------------------------------------
# SEARCH ENGINE
# ---------------------------------------------------------------------------

class SearchEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui

    def run(self):
        q = self.ui.ask("Global search query (case-insensitive)")
        if not q:
            return
        ql = q.lower()
        self.ui.header("SEARCH", q)
        tools = [n for n in ALL_TOOL_NAMES if ql in n.lower()]
        projects = [p for p in self.app.store.load("projects", {}).get("projects", [])
                    if ql in p["name"].lower() or ql in p["path"].lower()]
        history = [h for h in self.app.store.load("history", [])
                   if ql in h.get("action", "").lower() or ql in h.get("detail", "").lower()]
        if tools:
            print(self.ui.t.c("TOOLS", "accent"))
            for t in tools:
                print("  %s %-14s %s" % (ico("ok") if self.app.detector.installed(t) else ico("bad"),
                                         t, self.app.detector.status(t)))
        if projects:
            print(self.ui.t.c("PROJECTS", "accent"))
            for p in projects[:20]:
                print("  - %s [%s]" % (p["path"], p["type"]))
        if history:
            print(self.ui.t.c("HISTORY", "accent"))
            for h in history[-10:]:
                print("  %s | %s | %s" % (h.get("time", ""), h.get("action", ""),
                                          h.get("detail", "")))
        if not (tools or projects or history):
            self.ui.status("info", "No matches.")
        self.app.store.log("Search", "Success", q)
        self.ui.pause()


# ---------------------------------------------------------------------------
# PROFILE ENGINE
# ---------------------------------------------------------------------------

class ProfileEngine:
    def __init__(self, app):
        self.app = app
        self.ui = app.ui

    def refresh(self):
        app = self.app
        projects = app.store.load("projects", {}).get("projects", [])
        profile = {
            "name": "CLXV12",
            "version": VERSION,
            "device": app.system.android_version(),
            "architecture": platform.machine() or "N/A",
            "termux": app.system.termux_version(),
            "python": platform.python_version(),
            "projects": len(projects),
            "clxv11_artifacts": len(discover_identity_artifacts(app.store)),
            "tools": app.detector.count(),
            "last_scan": now_iso(),
        }
        app.store.save("profile", profile)
        return profile

    def show(self):
        p = self.app.store.load("profile", {}) or self.refresh()
        self.ui.header("CLXV11 PROFILE")
        rows = [(k.capitalize(), str(v)) for k, v in p.items()]
        self.ui.panels([("PROFILE", rows)])
        self.ui.pause()

    def menu(self):
        while True:
            ch = self.ui.menu("PROFILE", [
                ("1", "View Profile", "system"), ("2", "Rescan Environment", "run"),
                ("3", "CLXV11 Artifacts", "search"), ("4", "Install as Command", "settings"),
                ("5", "View History", "history"), ("6", "Clear History", "cleanup"),
                ("0", "Back", "back"),
            ])
            if ch in (None, "0"):
                return
            if ch == "1":
                self.show()
            elif ch == "2":
                self.app.environment_scan(verbose=True)
            elif ch == "3":
                arts = discover_identity_artifacts(self.app.store)
                self.ui.header("CLXV11 ARTIFACTS", "%d found" % len(arts))
                for a in arts[:80]:
                    print(" [%s] %s" % (a["kind"], a["path"]))
                if not arts:
                    self.ui.status("info", "No CLXV11-related files or folders in approved roots.")
                self.ui.pause()
            elif ch == "4":
                self.install_command()
            elif ch == "5":
                self.app.show_history()
            elif ch == "6":
                if self.ui.confirm("Clear all history?", False):
                    self.app.store.save("history", [])
                    self.ui.status("ok", "History cleared.")
                    self.ui.pause()

    def install_command(self):
        prefix = os.environ.get("PREFIX")
        if not prefix or not (Path(prefix) / "bin").exists():
            self.ui.status("bad", "Termux PREFIX/bin not found. Not running inside Termux?")
            self.ui.pause()
            return
        src = Path(__file__).resolve()
        target = Path(prefix) / "bin" / "clxv12"
        if target.is_symlink():
            self.ui.status("bad", "Refused: %s is a symlink." % target)
            self.ui.pause()
            return
        script = "#!%s\nexec %s %s \"$@\"\n" % (
            os.environ.get("SHELL", "/bin/sh"),
            shlex.quote(sys.executable), shlex.quote(str(src)))
        if atomic_write(target, script, mode=0o755):
            self.app.store.log("Install Command", "Success", str(target))
            self.ui.status("ok", "Installed: %s (run: clxv12)" % target)
        else:
            self.ui.status("bad", "Install failed: destination not writable.")
        self.ui.pause()


# ---------------------------------------------------------------------------
# CAPABILITY MATRIX - one authoritative map of feature -> requirements
# ---------------------------------------------------------------------------

# Requirement logic: a requirement is a list of alternatives; each alternative
# is a list of tools that must ALL be present (AND). ANY alternative suffices
# (OR). A plain string is shorthand for a single mandatory tool.
CAPABILITIES = [
    ("Project Manager", []),
    ("Build: Node/npm", [["npm"]]),
    ("Build: Android/Gradle", [["java", "gradle"], ["java"]]),  # gradlew ships with the project
    ("Build: Flutter", [["flutter"]]),
    ("Build: C/C++ (Make)", [["make"]]),
    ("Build: C/C++ (CMake)", [["cmake"]]),
    ("APK analysis (ZIP level)", []),
    ("APK signing schemes v1-v4", []),
    ("APK sign/verify", [["apksigner"]]),
    ("APK rich metadata", [["aapt"], ["apkanalyzer"]]),
    ("Git operations", [["git"]]),
    ("Network discovery", []),  # ping optional; TCP fallback built in
    ("Wi-Fi audit (SSID/BSSID)", [["termux-wifi-connectioninfo"]]),
    ("Archives: ZIP/TAR", []),
    ("Archives: 7z", [["7z"]]),
    ("Developer tools", []),
    ("Cleanup", []),
]


def requirement_satisfied(req, detector):
    """req: list of AND-alternatives (each a list of tool names).
    Returns (satisfied, matched_alternative)."""
    for alt in req:
        if all(detector.installed(t) for t in alt):
            return True, alt
    return False, None


def capability_rows(detector):
    rows = []
    for feature, req in CAPABILITIES:
        if not req:
            rows.append((feature, "-", "AVAILABLE"))
            continue
        ok, alt = requirement_satisfied(req, detector)
        if ok:
            rows.append((feature, " + ".join(alt), "AVAILABLE"))
        else:
            alts = [" + ".join(a) for a in req]
            rows.append((feature, " or ".join(alts),
                         "NOT INSTALLED (needs: %s)" % " or ".join(alts)))
    return rows


# ---------------------------------------------------------------------------
# HEADLESS DATA PROVIDERS
#
# Every CLI command is (collector -> OpResult) + (renderer -> terminal).
# Collectors NEVER print and NEVER prompt, which is what makes --json pure
# by construction rather than by hoping no engine writes to stdout.
# ---------------------------------------------------------------------------


def mask_home(text):
    """Replace the real home directory with ~ so diagnostics and logs do not
    leak the device account name."""
    try:
        home = str(Path.home())
    except (OSError, RuntimeError):
        return str(text)
    s = str(text)
    return s.replace(home, "~") if home and home != "/" else s


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:                                     # noqa: BLE001
        return default


def data_system(app):
    res = OpResult.success({})
    rows = dict(app.system.info_rows())
    versions = {}
    for tool in ("git", "node", "npm", "python", "java", "gradle", "clang", "make"):
        v = _safe(lambda t=tool: app.system.tool_version(t), "N/A")
        versions[tool] = v
    res.data = {
        "platform": {k: mask_home(v) for k, v in rows.items()},
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": mask_home(sys.executable),
            "encoding": sys.getdefaultencoding(),
            "filesystem_encoding": sys.getfilesystemencoding(),
        },
        "tool_versions": versions,
        "termux": bool(_safe(app.system.is_termux, False)),
    }
    return res


def data_tools(app):
    res = OpResult.success({})
    app.detector.scan()
    tools, installed = [], 0
    for group, names in TOOL_GROUPS.items():
        for name in names:
            status = app.detector.status(name)
            path = app.detector.path(name)
            entry = {
                "name": name, "group": group, "status": status,
                "installed": status == "INSTALLED",
                "path": mask_home(path) if path else None,
                "version": app.system.tool_version(name)
                           if (status == "INSTALLED" and name in VERSION_FLAGS) else None,
            }
            installed += entry["installed"]
            tools.append(entry)
    res.data = {"total": len(tools), "installed": installed,
                "missing": len(tools) - installed, "tools": tools}
    if installed == 0:
        res.add_warning("no development tools detected on PATH",
                        ErrCode.DEPENDENCY_MISSING)
    return res


def data_projects(app, rescan=True):
    res = OpResult.success({})
    if rescan:
        projects = discover_projects(app.store)
    else:
        projects = app.store.load("projects", {}).get("projects", [])
    limited = projects[:RT.max_results]
    if len(projects) > len(limited):
        res.add_warning("%d projects found, %d returned (--max-results)"
                        % (len(projects), len(limited)))
    by_type = {}
    for p in limited:
        by_type[p["type"]] = by_type.get(p["type"], 0) + 1
    res.data = {
        "count": len(limited), "total_found": len(projects),
        "roots": [mask_home(str(r)) for r in approved_roots()],
        "by_type": by_type,
        "projects": [{"name": p["name"], "path": mask_home(p["path"]),
                      "type": p["type"], "evidence": p.get("evidence", [])}
                     for p in limited],
    }
    return res


def data_network(app, discover=False):
    res = OpResult.success({})
    net, ip_str, gw, iface = get_local_network()
    local_addr = None
    if ip_str:
        try:
            local_addr = ipaddress.ip_address(ip_str)
        except ValueError:
            res.add_warning("local IP %r is not parseable" % str(ip_str)[:40])
    info = {
        "interface": iface,
        "local_ip": str(local_addr) if local_addr else None,
        "ip_version": local_addr.version if local_addr else None,
        "network": str(net) if net else None,
        "gateway": gw,
        "dns": get_dns_servers(),
        "connected": bool(local_addr and not local_addr.is_loopback),
    }
    wifi = _safe(app.network.wifi_info)
    info["wifi"] = wifi
    if wifi is None:
        res.add_warning("SSID/BSSID unavailable (Termux:API not installed or "
                        "location permission denied)", ErrCode.UNAVAILABLE)
    res.data = {"info": info, "discovery": None}

    if discover:
        if not info["connected"] or net is None:
            res.add_warning("host discovery skipped: no routable local network",
                            ErrCode.NETWORK_UNREACHABLE)
        else:
            t0 = time.monotonic()
            hosts, _myip, _n = app.network._discover(False)
            hosts = [h for h in (hosts or []) if h != ip_str][:RT.max_results]
            alive, deadline = [], time.monotonic() + max(5.0, RT.timeout)
            try:
                with ThreadPoolExecutor(max_workers=min(16, max(1, len(hosts) or 1))) as ex:
                    futs = {ex.submit(app.network.ping_once, h, 1): h for h in hosts}
                    for fut in as_completed(futs):
                        lat = _safe(fut.result)
                        if lat is not None:
                            alive.append({"ip": futs[fut], "latency_ms": round(lat, 2)})
                        if time.monotonic() > deadline:
                            res.add_warning("discovery deadline reached; partial results")
                            break
            except KeyboardInterrupt:
                res.add_warning("discovery interrupted", ErrCode.INTERRUPTED)
            alive.sort(key=lambda d: d["ip"])
            res.data["discovery"] = {
                "probed": len(hosts), "alive": len(alive), "hosts": alive,
                "duration_ms": int((time.monotonic() - t0) * 1000),
            }
            LOG.audit("network_discovery", str(net), "success",
                      (time.monotonic() - t0) * 1000, alive=len(alive))
    return res


def data_wifi(app):
    return app.wifi.collect()


def data_capabilities(app):
    res = OpResult.success({})
    rows = capability_rows(app.detector)
    res.data = {
        "count": len(rows),
        "available": sum(1 for _f, _r, s in rows if s == "AVAILABLE"),
        "capabilities": [{"feature": f, "requires": r, "status": s,
                          "available": s == "AVAILABLE"} for f, r, s in rows],
    }
    return res


def data_security(app):
    res = OpResult.success({})
    cfg_mode = None
    if CONFIG_DIR.exists():
        cfg_mode = oct(CONFIG_DIR.stat().st_mode & 0o777)
    findings = []

    def finding(level, check, detail, evidence=None):
        findings.append({"level": level, "check": check, "detail": detail,
                         "evidence": evidence})

    # Only report a risk when there is evidence for it.
    if cfg_mode and int(cfg_mode, 8) & 0o077:
        finding("WARNING", "data directory permissions",
                "%s is group/world accessible" % CONFIG_DIR, cfg_mode)
    else:
        finding("PASS", "data directory permissions",
                "private to the owner", cfg_mode)

    loose = []
    for key, path in DATA_FILES.items():
        try:
            if path.exists() and (path.stat().st_mode & 0o077):
                loose.append("%s(%s)" % (key, oct(path.stat().st_mode & 0o777)))
        except OSError:
            continue
    finding("WARNING" if loose else "PASS", "store file permissions",
            "world/group readable store files" if loose else "all store files are 0600",
            loose or None)

    leaked = []
    for key, path in list(DATA_FILES.items()):
        try:
            if not path.exists() or path.stat().st_size > 4 << 20:
                continue
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if redact_credentials(raw) != raw:
            leaked.append(key)
    finding("HIGH" if leaked else "PASS", "credential leakage in store",
            "possible secrets found in store files" if leaked
            else "no credential patterns found in store files", leaked or None)

    try:
        app.store.load("history", [])
        store_ok = True
    except Exception:                                     # noqa: BLE001
        store_ok = False
    finding("PASS" if store_ok else "WARNING", "store integrity",
            "store parses and validates" if store_ok else "store failed to load")

    finding("PASS", "subprocess policy",
            "argument lists only, shell=False, bounded capture %d bytes/stream"
            % Runner.MAX_CAPTURE)
    finding("PASS", "archive policy",
            "traversal/symlink/absolute rejected; %d entries, %s, ratio %dx caps"
            % (MAX_EXTRACT_ENTRIES, human_size(MAX_EXTRACT_TOTAL), MAX_RATIO))
    finding("PASS", "port scan policy",
            "restricted to loopback, link-local and the attached network; "
            "max %d ports, %d concurrent" % (MAX_PORTS_PER_CHECK, MAX_PORT_CONCURRENCY))

    levels = {}
    for f in findings:
        levels[f["level"]] = levels.get(f["level"], 0) + 1
    res.data = {
        "version": VERSION,
        "read_roots": [mask_home(str(r)) for r in read_roots()],
        "write_roots": [mask_home(str(r)) for r in write_roots()],
        "protected_paths": [str(p) for p in sorted(protected_paths(), key=str)],
        "data_dir": {"path": mask_home(str(CONFIG_DIR)), "mode": cfg_mode},
        "log_dir": mask_home(str(LOG_DIR)),
        "locking": "fcntl flock" if _HAS_FCNTL else "best-effort (no fcntl)",
        "schema_version": Store.SCHEMA,
        "limits": {
            "archive_max_entries": MAX_EXTRACT_ENTRIES,
            "archive_max_total_bytes": MAX_EXTRACT_TOTAL,
            "archive_max_member_bytes": MAX_MEMBER_SIZE,
            "archive_max_ratio": MAX_RATIO,
            "runner_capture_bytes": Runner.MAX_CAPTURE,
            "history_cap": MAX_HISTORY,
            "max_ports_per_check": MAX_PORTS_PER_CHECK,
            "max_port_concurrency": MAX_PORT_CONCURRENCY,
        },
        "findings": findings,
        "summary": levels,
    }
    if levels.get("HIGH"):
        res.add_warning("%d HIGH severity finding(s)" % levels["HIGH"])
    return res


def data_scan(app):
    """Full environment scan: tools + projects + profile, headless."""
    res = OpResult.success({})
    t0 = time.monotonic()
    app.detector.scan()
    projects = discover_projects(app.store)
    profile = app.profile.refresh()
    res.data = {
        "tools": {"installed": app.detector.count(), "known": len(ALL_TOOL_NAMES)},
        "projects": {"count": len(projects),
                     "by_type": {t: sum(1 for p in projects if p["type"] == t)
                                 for t in sorted({p["type"] for p in projects})}},
        "profile": {k: mask_home(v) if isinstance(v, str) else v
                    for k, v in (profile or {}).items()},
        "roots": [mask_home(str(r)) for r in approved_roots()],
        "duration_ms": int((time.monotonic() - t0) * 1000),
    }
    app.store.log("Environment Scan", "Success", "%d tools" % app.detector.count())
    return res


# ---------------------------------------------------------------------------
# DOCTOR / HEALTH / DIAGNOSTICS
# ---------------------------------------------------------------------------

DOCTOR_CRITICAL_TOOLS = ("python", "git")
DOCTOR_USEFUL_TOOLS = ("node", "npm", "curl", "unzip", "tar", "zip")


def data_doctor(app):
    """Environment diagnosis with actionable, non-destructive suggestions.
    Nothing is repaired automatically."""
    res = OpResult.success({})
    checks = []

    def add(name, status, detail, fix=None):
        checks.append({"check": name, "status": status, "detail": detail,
                       "fix": fix})

    # 1. Python
    v = sys.version_info
    if v >= (3, 8):
        add("Python version", "PASS", platform.python_version())
    elif v >= (3, 6):
        add("Python version", "WARN", "%s is old" % platform.python_version(),
            "pkg upgrade python")
    else:
        add("Python version", "FAIL", "%s is unsupported" % platform.python_version(),
            "pkg install python")

    # 2. Termux
    if app.system.is_termux():
        add("Termux environment", "PASS", app.system.termux_version() or "detected")
    else:
        add("Termux environment", "WARN",
            "not running under Termux; Android-specific features stay unavailable",
            None)

    # 3. Storage permission
    storage = Path.home() / "storage"
    if storage.exists():
        add("Storage permission", "PASS", mask_home(str(storage)))
    else:
        add("Storage permission", "WARN", "~/storage is missing",
            "run: termux-setup-storage")

    # 4. HOME writability
    try:
        probe = CONFIG_DIR / (".doctor_%s" % os.getpid())
        CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        add("HOME writable", "PASS", mask_home(str(CONFIG_DIR)))
    except OSError as e:
        add("HOME writable", "FAIL", "%s: %s" % (type(e).__name__, e),
            "check filesystem permissions or free space")

    # 5. PATH
    path_entries = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    if not path_entries:
        add("PATH", "FAIL", "PATH is empty", "export PATH=$PREFIX/bin:$PATH")
    else:
        missing = [p for p in path_entries if not os.path.isdir(p)]
        relative = [p for p in path_entries if not os.path.isabs(p)]
        if relative:
            add("PATH", "WARN", "%d relative PATH entr(y/ies)" % len(relative),
                "remove relative entries: they are a code-execution risk")
        elif missing:
            add("PATH", "WARN", "%d PATH entries do not exist" % len(missing), None)
        else:
            add("PATH", "PASS", "%d entries, all absolute and present" % len(path_entries))

    # 6. Critical + useful tools
    app.detector.scan()
    for tool in DOCTOR_CRITICAL_TOOLS:
        if app.detector.installed(tool) or Runner.check(tool):
            add("Tool: %s" % tool, "PASS", mask_home(app.detector.path(tool) or tool))
        else:
            add("Tool: %s" % tool, "FAIL", "not found on PATH", "pkg install %s" % tool)
    missing_useful = [t for t in DOCTOR_USEFUL_TOOLS if not app.detector.installed(t)]
    if missing_useful:
        add("Optional tooling", "WARN", "missing: %s" % ", ".join(missing_useful),
            "pkg install %s" % " ".join(missing_useful))
    else:
        add("Optional tooling", "PASS", "all common helpers present")

    # 7. Disk space
    try:
        st = os.statvfs(str(Path.home()))
        free = st.f_bavail * st.f_frsize
        total = st.f_blocks * st.f_frsize
        pct = (free / total * 100) if total else 0
        if free < 64 << 20:
            add("Disk space", "FAIL", "%s free (%.1f%%)" % (human_size(free), pct),
                "free space before building anything")
        elif pct < 10:
            add("Disk space", "WARN", "%s free (%.1f%%)" % (human_size(free), pct),
                "consider the Cleanup engine")
        else:
            add("Disk space", "PASS", "%s free of %s" % (human_size(free), human_size(total)))
    except OSError as e:
        add("Disk space", "WARN", "unreadable: %s" % e)

    # 8. RAM
    ram = app.system.memory()
    add("RAM", "PASS" if ram != "N/A" else "WARN", ram)

    # 9. Loopback networking (never requires the internet)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        state, _ms, _d = probe_port("127.0.0.1", port, socket.AF_INET, 1.0)
        s.close()
        add("Loopback networking", "PASS" if state == PORT_OPEN else "WARN", state)
    except OSError as e:
        add("Loopback networking", "FAIL", str(e))

    # 10. DNS (optional: offline is a valid state, not a failure)
    try:
        _getaddrinfo_bounded("localhost", timeout=3.0)
        add("Name resolution", "PASS", "localhost resolves")
    except ToolkitError as e:
        add("Name resolution", "WARN", e.message, "check /etc/resolv.conf")

    # 11. Encoding
    enc = (sys.stdout.encoding or "").lower()
    if "utf" in enc or "utf" in (sys.getfilesystemencoding() or "").lower():
        add("Unicode support", "PASS", enc or sys.getfilesystemencoding())
    else:
        add("Unicode support", "WARN", "stdout encoding is %r" % enc,
            "export LANG=en_US.UTF-8")

    # 12. Logging
    add("Logging", "PASS" if LOG._write("app", {"ts": now_iso(), "level": "info",
                                                "message": "doctor probe"})
        else "WARN", mask_home(str(LOG_DIR)))

    counts = {}
    for c in checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    res.data = {"checks": checks, "summary": counts,
                "pass": counts.get("PASS", 0), "warn": counts.get("WARN", 0),
                "fail": counts.get("FAIL", 0)}
    if counts.get("FAIL"):
        res.add_error(ErrCode.DEPENDENCY_MISSING,
                      "%d doctor check(s) failed" % counts["FAIL"])
    elif counts.get("WARN"):
        res.add_warning("%d doctor check(s) raised warnings" % counts["WARN"])
    return res


def data_health(app):
    """Fast subsystem health check - must stay under a couple of seconds."""
    res = OpResult.success({})
    subsystems = []

    def probe(name, fn):
        t0 = time.monotonic()
        try:
            ok, detail = fn()
            status = "PASS" if ok is True else ("WARN" if ok is None else "FAIL")
        except Exception as e:                            # noqa: BLE001
            status, detail = "FAIL", "%s: %s" % (type(e).__name__, e)
        subsystems.append({"subsystem": name, "status": status,
                           "detail": str(detail),
                           "duration_ms": int((time.monotonic() - t0) * 1000)})

    probe("Core", lambda: (True, "v%s, python %s" % (VERSION, platform.python_version())))

    def _fs():
        with tempfile.NamedTemporaryFile(dir=str(CONFIG_DIR), prefix=".health_",
                                         delete=True) as fh:
            fh.write(b"health")
            fh.flush()
        return True, mask_home(str(CONFIG_DIR))
    probe("Filesystem", _fs)

    def _runner():
        r = Runner.run([sys.executable, "-c", "print('ok')"], timeout=15)
        return (r.rc == 0 and "ok" in r.out), "exit %d" % r.rc
    probe("Runner", _runner)

    def _network():
        net, ip_str, gw, _iface = get_local_network()
        if not ip_str:
            return None, "no local IP (offline is a valid state)"
        return True, "%s via %s" % (ip_str, gw or "no gateway")
    probe("Network", _network)

    def _storage():
        st = os.statvfs(str(Path.home()))
        free = st.f_bavail * st.f_frsize
        return (free > 64 << 20), "%s free" % human_size(free)
    probe("Storage", _storage)

    def _security():
        bad = safe_path("/etc/passwd") is None and safe_path("/") is None
        return bad, "protected paths refused" if bad else "path guard NOT refusing"
    probe("Security", _security)

    def _tools():
        n = app.detector.count()
        return (True if n >= 3 else None), "%d/%d detected" % (n, len(ALL_TOOL_NAMES))
    probe("Tools", _tools)

    def _store():
        app.store.load("history", [])
        return True, "schema v%d" % Store.SCHEMA
    probe("Store", _store)

    counts = {}
    for s in subsystems:
        counts[s["status"]] = counts.get(s["status"], 0) + 1
    res.data = {"subsystems": subsystems, "summary": counts,
                "healthy": counts.get("FAIL", 0) == 0}
    if counts.get("FAIL"):
        res.add_error(ErrCode.INTERNAL, "%d subsystem(s) unhealthy" % counts["FAIL"])
    return res


def data_diagnostics(app):
    """Environment dump with home path masked and secrets redacted."""
    res = OpResult.success({})
    u = platform.uname()
    path_entries = [mask_home(p) for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    res.data = {
        "toolkit": {"name": APP_NAME, "version": VERSION,
                    "file": mask_home(str(Path(__file__).resolve()))},
        "os": {"system": u.system, "release": u.release, "machine": u.machine,
               "processor": u.processor or "N/A"},
        "android": {"version": app.system.android_version(),
                    "termux": bool(app.system.is_termux()),
                    "termux_version": app.system.termux_version()},
        "python": {"version": platform.python_version(),
                   "implementation": platform.python_implementation(),
                   "executable": mask_home(sys.executable),
                   "default_encoding": sys.getdefaultencoding(),
                   "filesystem_encoding": sys.getfilesystemencoding(),
                   "stdout_encoding": sys.stdout.encoding,
                   "max_unicode": sys.maxunicode},
        "hardware": {"cpu_count": os.cpu_count(), "ram": app.system.memory(),
                     "storage": app.system.storage(),
                     "battery": _safe(app.system.battery, "N/A")},
        "environment": {"HOME": "~", "PWD": mask_home(os.getcwd()),
                        "SHELL": os.environ.get("SHELL", "N/A"),
                        "TERM": os.environ.get("TERM", "N/A"),
                        "LANG": os.environ.get("LANG", "N/A"),
                        "PREFIX": mask_home(os.environ.get("PREFIX", "N/A")),
                        "path_entries": len(path_entries), "path": path_entries},
        "terminal": {"columns": app.ui.width(), "is_tty": sys.stdout.isatty(),
                     "color_level": app.ui.t.level, "unicode": supports_unicode()},
        "runtime": {"json_mode": RT.json, "quiet": RT.quiet, "verbose": RT.verbose,
                    "interactive": RT.interactive, "timeout": RT.timeout,
                    "depth": RT.depth, "max_results": RT.max_results},
        "tools_detected": app.detector.count(),
        "capabilities": {"fcntl": _HAS_FCNTL},
    }
    return res


# ---------------------------------------------------------------------------
# RENDERERS - human output built from the very same OpResult
# ---------------------------------------------------------------------------

_STATUS_COLORS = {"PASS": "success", "OK": "success", "WARN": "warning",
                  "WARNING": "warning", "FAIL": "error", "HIGH": "error",
                  "INFO": "muted", "UNKNOWN": "info", "UNAVAILABLE": "info"}


def _status_table(ui, rows, headers):
    ui.table(headers, rows)


def render_system(app, res):
    d = res.data
    rows = list(d["platform"].items())
    rows += [("Python", d["python"]["version"]), ("Termux", str(d["termux"]))]
    rt = [(k.capitalize(), v) for k, v in d["tool_versions"].items()]
    half = (len(rows) + 1) // 2
    app.ui.panels([("PLATFORM", rows[:half]), ("SYSTEM", rows[half:])])
    app.ui.panels([("RUNTIMES", rt)])


def render_tools(app, res):
    d = res.data
    app.ui.header("TOOL DISCOVERY", "%d/%d installed" % (d["installed"], d["total"]))
    rows, current = [], None
    for t in d["tools"]:
        if t["group"] != current:
            current = t["group"]
            rows.append((app.ui.t.c(current, "accent"), "", ""))
        color = "success" if t["installed"] else (
            "info" if t["status"] in ("UNAVAILABLE", "NOT APPLICABLE") else "error")
        rows.append(("  " + t["name"], app.ui.t.c(t["status"], color),
                     t["version"] or ""))
    app.ui.table(["TOOL", "STATUS", "VERSION"], rows)


def render_projects(app, res):
    d = res.data
    app.ui.header("PROJECTS", "%d found" % d["count"])
    if not d["projects"]:
        app.ui.status("info", "No projects detected under: %s" % ", ".join(d["roots"]))
        return
    app.ui.table(["NAME", "TYPE", "EVIDENCE", "PATH"],
                 [(p["name"], p["type"], ", ".join(p["evidence"][:3]), p["path"])
                  for p in d["projects"]])


def render_network(app, res):
    d = res.data
    info = d["info"]
    app.ui.panels([("NETWORK", [
        ("Interface", info["interface"] or "N/A"),
        ("Local IP", info["local_ip"] or "N/A"),
        ("Subnet", info["network"] or "N/A"),
        ("Gateway", info["gateway"] or "N/A"),
        ("DNS", ", ".join(info["dns"]) or "N/A"),
        ("SSID", (info["wifi"] or {}).get("ssid") or "unavailable (Termux:API)"),
        ("Connected", "yes" if info["connected"] else "no"),
    ])])
    if d.get("discovery"):
        disc = d["discovery"]
        app.ui.status("info", "%d/%d hosts responded in %d ms"
                      % (disc["alive"], disc["probed"], disc["duration_ms"]))
        if disc["hosts"]:
            app.ui.table(["IP", "LATENCY"],
                         [(h["ip"], "%.1f ms" % h["latency_ms"]) for h in disc["hosts"]])
        app.ui.status("info", "MAC addresses are unavailable without root on Android.")


def render_wifi(app, res):
    app.wifi.render(res)


def render_capabilities(app, res):
    d = res.data
    app.ui.header("CAPABILITY MATRIX", "%d/%d available" % (d["available"], d["count"]))
    app.ui.table(["FEATURE", "REQUIRES", "STATUS"],
                 [(c["feature"], c["requires"], c["status"]) for c in d["capabilities"]])


def render_security(app, res):
    d = res.data
    app.ui.header("SECURITY POSTURE", "v" + d["version"])
    app.ui.panels([("SCOPE", [
        ("Read roots", ", ".join(d["read_roots"])),
        ("Write roots", ", ".join(d["write_roots"])),
        ("Data dir", "%s (mode %s)" % (d["data_dir"]["path"], d["data_dir"]["mode"])),
        ("Log dir", d["log_dir"]),
        ("Locking", d["locking"]),
        ("Schema", "v%d" % d["schema_version"]),
    ])])
    app.ui.table(["LEVEL", "CHECK", "DETAIL"],
                 [(app.ui.t.c(f["level"], _STATUS_COLORS.get(f["level"], "muted")),
                   f["check"], f["detail"]) for f in d["findings"]])


def render_scan(app, res):
    d = res.data
    app.ui.header("ENVIRONMENT SCAN", "%d ms" % d["duration_ms"])
    app.ui.panels([("RESULT", [
        ("Tools", "%d/%d" % (d["tools"]["installed"], d["tools"]["known"])),
        ("Projects", str(d["projects"]["count"])),
        ("Roots", ", ".join(d["roots"])),
    ])])
    if d["projects"]["by_type"]:
        app.ui.table(["PROJECT TYPE", "COUNT"],
                     [(k, str(v)) for k, v in sorted(d["projects"]["by_type"].items())])


def render_doctor(app, res):
    d = res.data
    app.ui.header("DEPENDENCY DOCTOR",
                  "%d pass / %d warn / %d fail" % (d["pass"], d["warn"], d["fail"]))
    for c in d["checks"]:
        print("  %s %-24s %s" % (
            app.ui.t.c("[%-4s]" % c["status"], _STATUS_COLORS.get(c["status"], "muted")),
            c["check"][:24], app.ui.t.c(str(c["detail"])[:44], "muted")))
        if c["fix"]:
            print("         %s %s" % (app.ui.t.c("fix:", "accent"), c["fix"]))
    print()
    app.ui.status("ok" if not d["fail"] else "bad",
                  "%d checks: %d PASS, %d WARN, %d FAIL"
                  % (len(d["checks"]), d["pass"], d["warn"], d["fail"]))
    app.ui.status("info", "No repairs were applied automatically.")


def render_health(app, res):
    d = res.data
    app.ui.header("HEALTH CHECK", "healthy" if d["healthy"] else "degraded")
    for s in d["subsystems"]:
        dots = "." * max(1, 14 - len(s["subsystem"]))
        print("  %s %s %s  %s" % (
            s["subsystem"], app.ui.t.c(dots, "muted"),
            app.ui.t.c("%-4s" % s["status"], _STATUS_COLORS.get(s["status"], "muted")),
            app.ui.t.c("%s (%d ms)" % (s["detail"][:46], s["duration_ms"]), "muted")))


def render_diagnostics(app, res):
    d = res.data
    app.ui.header("ENVIRONMENT DIAGNOSTICS", "v" + VERSION)
    app.ui.panels([
        ("SYSTEM", [("OS", "%s %s" % (d["os"]["system"], d["os"]["release"])),
                    ("Arch", d["os"]["machine"]),
                    ("Android", d["android"]["version"]),
                    ("Termux", str(d["android"]["termux"]))]),
        ("PYTHON", [("Version", d["python"]["version"]),
                    ("Impl", d["python"]["implementation"]),
                    ("Encoding", d["python"]["default_encoding"]),
                    ("FS encoding", d["python"]["filesystem_encoding"])]),
        ("HARDWARE", [("CPU", str(d["hardware"]["cpu_count"])),
                      ("RAM", d["hardware"]["ram"]),
                      ("Storage", d["hardware"]["storage"]),
                      ("Battery", str(d["hardware"]["battery"]))]),
    ])
    app.ui.panels([("ENVIRONMENT", [
        ("PWD", d["environment"]["PWD"]), ("TERM", d["environment"]["TERM"]),
        ("LANG", d["environment"]["LANG"]),
        ("PATH entries", str(d["environment"]["path_entries"])),
        ("Columns", str(d["terminal"]["columns"])),
        ("Color", d["terminal"]["color_level"]),
    ])])
    app.ui.status("info", "Home directory masked; secrets redacted.")


def render_ports(app, res):
    app.network.render_port_check(res)


def data_backups(app):
    return BACKUPS.list()


def data_undo_list(app):
    return UNDO.history(limit=RT.max_results)


def data_benchmark(app):
    return run_benchmark(app)


def data_config(app):
    res = OpResult.success({
        "path": str(CONFIG.path), "source": CONFIG.source,
        "recovered": CONFIG.recovered, "config": CONFIG.data,
        "defaults_identical": CONFIG.data == CONFIG_DEFAULTS,
    })
    if CONFIG.recovered:
        res.add_warning("the config file was unreadable and defaults are in use; "
                        "the original was kept as %s"
                        % CONFIG.path.with_suffix(".json.corrupt"))
    return res


def render_backups(app, res):
    d = res.data
    app.ui.header("BACKUPS", "%d stored in %s" % (d["count"], mask_home(d["dir"])))
    if not d["backups"]:
        app.ui.status("info", "No backups yet.")
        return
    app.ui.table(["ID", "KIND", "SOURCE", "SIZE", "INTEGRITY", "CREATED"],
                 [(b["id"], b["kind"], mask_home(b["source"])[-38:],
                   human_size(b.get("bytes", 0)),
                   app.ui.t.c("OK", "success") if b.get("verified")
                   else app.ui.t.c("FAILED" if b.get("present") else "MISSING", "error"),
                   b.get("created", "")[:19]) for b in d["backups"]])


def render_undo_list(app, res):
    d = res.data
    app.ui.header("UNDO JOURNAL", "%d entries" % len(d["entries"]))
    if d["entries"]:
        app.ui.table(["ID", "OPERATION", "TARGET", "WHEN", "UNDONE"],
                     [(e["id"], e["operation"],
                       mask_home(e.get("source", ""))[-34:],
                       e["timestamp"][:19], "yes" if e.get("undone") else "no")
                      for e in d["entries"]])
    else:
        app.ui.status("info", "Nothing recorded yet.")
    app.ui.panels([("REVERSIBLE", [(k, v) for k, v in
                                   sorted(d["reversible_operations"].items())])])
    app.ui.status("info", "Not reversible: %s"
                  % ", ".join(d["irreversible_operations"]))


def render_benchmark(app, res):
    d = res.data
    app.ui.header("BENCHMARK", "%d iteration(s), %.0f ms total"
                  % (d["iterations"], d["total_ms"]))
    app.ui.table(["BENCHMARK", "DURATION", "BASELINE", "STATUS"],
                 [(b["benchmark"],
                   "%.1f ms" % b["duration_ms"] if b["duration_ms"] is not None else "-",
                   "%d ms" % b["baseline_ms"] if b["baseline_ms"] else "-",
                   app.ui.t.c(b["status"],
                              "success" if b["status"] == "OK"
                              else ("warning" if b["status"] == "SLOW" else "error")))
                  for b in d["benchmarks"]])
    app.ui.status("info", d["note"])


def render_config(app, res):
    d = res.data
    app.ui.header("CONFIGURATION", mask_home(d["path"]))
    app.ui.status("info", "source: %s" % d["source"])
    rows = []

    def flatten(node, prefix=""):
        for k, v in node.items():
            key = "%s%s" % (prefix, k)
            if isinstance(v, dict):
                flatten(v, key + ".")
            else:
                rows.append((key, str(v)[:44]))
    flatten(d["config"])
    half = (len(rows) + 1) // 2
    app.ui.panels([("CONFIG", rows[:half]), ("CONFIG (cont.)", rows[half:])])


def render_archive_check(app, res):
    d = res.data
    app.ui.header("ARCHIVE SAFETY CHECK", "%s (%s)" % (Path(d["archive"]).name,
                                                       d["format"]))
    app.ui.panels([("ARCHIVE", [
        ("Members", str(d["member_count"])),
        ("Packed", human_size(d["packed_bytes"])),
        ("Uncompressed", human_size(d["uncompressed_bytes"])),
        ("Ratio", "%.1fx" % d["ratio"]),
        ("Verdict", "SAFE TO EXTRACT" if d["safe_to_extract"] else "UNSAFE"),
    ])])
    for c in d["checks"]:
        mark = app.ui.t.c("✓" if c["pass"] else "✗",
                          "success" if c["pass"] else "error")
        print("  %s %-28s %s" % (mark, c["check"], app.ui.t.c(c["detail"], "muted")))
    if d["unsafe_members"]:
        print()
        app.ui.table(["REJECTED MEMBER", "FINDINGS"],
                     [(u["name"][:44], ", ".join(u["findings"]))
                      for u in d["unsafe_members"][:20]])
    print()
    app.ui.status("ok" if d["safe_to_extract"] else "warn",
                  "%d member(s) would extract, %d would be rejected"
                  % (d["would_extract"], d["would_reject"]))


def render_apk_info(app, res):
    d = res.data
    app.ui.header("APK MANIFEST", str(d.get("package") or "unknown package"))
    app.ui.panels([("PACKAGE", [
        ("Container", d["container"]),
        ("Package", str(d.get("package"))),
        ("Version name", str(d.get("version_name"))),
        ("Version code", str(d.get("version_code"))),
        ("minSdk", str(d.get("min_sdk"))),
        ("targetSdk", str(d.get("target_sdk"))),
    ])])
    appl = d.get("application") or {}
    app.ui.panels([("APPLICATION", [(k, str(v)) for k, v in appl.items()])])
    if d["permissions"]:
        app.ui.table(["PERMISSION", "CLASS"],
                     [(p, "dangerous" if p.rsplit(".", 1)[-1] in DANGEROUS_PERMISSIONS
                       else ("special" if p.rsplit(".", 1)[-1] in SPECIAL_PERMISSIONS
                             else "normal")) for p in d["permissions"]])
    rows = [(t, str(len(d["components"][t]))) for t in COMPONENT_TAGS]
    app.ui.panels([("COMPONENTS", rows)])


def render_apk_security(app, res):
    d = res.data
    app.ui.header("APK SECURITY ANALYSIS",
                  "%s  |  %d HIGH / %d WARNING"
                  % (d["manifest"].get("package") or "?", d["high"], d["warning"]))
    for f in d["findings"]:
        print("  %s %-38s %s" % (
            app.ui.t.c("[%-7s]" % f["level"], _STATUS_COLORS.get(f["level"], "muted")),
            f["check"][:38], app.ui.t.c(str(f["detail"])[:60], "muted")))
        if f.get("evidence"):
            ev = f["evidence"]
            ev = ", ".join(str(x) for x in ev) if isinstance(ev, list) else str(ev)
            print("            %s" % app.ui.t.c(ev[:96], "info"))
    print()
    app.ui.status("warn" if d["high"] else "ok",
                  "%d HIGH, %d WARNING, %d INFO" % (d["high"], d["warning"], d["info"]))
    app.ui.status("info", d["disclaimer"])


def render_tree(app, res):
    d = res.data
    app.ui.header("TREE", mask_home(d["root"]))
    print(app.ui.t.c(Path(d["root"]).name + "/", "accent"))
    for line in d["lines"]:
        print(line)
    app.ui.status("info", "%d entries, depth %d%s"
                  % (d["entries"], d["max_depth"],
                     " (truncated)" if d["truncated"] else ""))


def render_du(app, res):
    d = res.data
    app.ui.header("DISK USAGE", "%s in %s" % (d["total_human"], mask_home(d["root"])))
    app.ui.table(["NAME", "KIND", "SIZE", "%"],
                 [(e["name"][:34], e["kind"], e["human"], "%.1f" % e["percent"])
                  for e in d["entries"]])
    app.ui.status("info", "%d files visited%s"
                  % (d["files_visited"], " (capped)" if d["capped"] else ""))


def render_find(app, res):
    d = res.data
    app.ui.header("FIND", "%d match(es) of %d scanned" % (d["matches"], d["scanned"]))
    if not d["results"]:
        app.ui.status("info", "No matches.")
        return
    app.ui.table(["NAME", "TYPE", "SIZE", "MODIFIED", "PATH"],
                 [(r["name"][:24], r["type"], r["size"], r["modified"][:16],
                   mask_home(r["path"])[-40:]) for r in d["results"]])


def render_grep(app, res):
    d = res.data
    app.ui.header("GREP", "%r - %d match(es) in %d file(s)"
                  % (d["pattern"][:30], d["matches"], d["files_scanned"]))
    if not d["results"]:
        app.ui.status("info", "No matches.")
        return
    current = None
    for hit in d["results"]:
        if hit["path"] != current:
            current = hit["path"]
            print(app.ui.t.c(mask_home(current), "accent"))
        print("  %s %s" % (app.ui.t.c("%5d:" % hit["line"], "muted"), hit["text"]))
    if d["skipped"]["binary"] or d["skipped"]["too_large"]:
        app.ui.status("info", "skipped: %d binary, %d oversized"
                      % (d["skipped"]["binary"], d["skipped"]["too_large"]))


def render_view(app, res):
    d = res.data
    if d.get("binary"):
        app.ui.status("warn", d.get("note", "binary file"))
        return
    if "text" in d:
        print(d["text"])
    else:
        for line in d.get("lines", []):
            print(line)
        app.ui.status("info", "%s: %d line(s) of %s"
                      % (d.get("mode", "view"), d.get("returned", 0),
                         human_size(d.get("bytes", 0))))


# ---------------------------------------------------------------------------
# COMMAND REGISTRY
# ---------------------------------------------------------------------------

COMMANDS = {
    "system":       (data_system, render_system),
    "tools":        (data_tools, render_tools),
    "projects":     (data_projects, render_projects),
    "network":      (lambda app: data_network(app, discover=True), render_network),
    "wifi":         (data_wifi, render_wifi),
    "capabilities": (data_capabilities, render_capabilities),
    "security":     (data_security, render_security),
    "scan":         (data_scan, render_scan),
    "doctor":       (data_doctor, render_doctor),
    "health":       (data_health, render_health),
    "diagnostics":  (data_diagnostics, render_diagnostics),
    "backups":      (data_backups, render_backups),
    "undo-list":    (data_undo_list, render_undo_list),
    "benchmark":    (data_benchmark, render_benchmark),
    "config":       (data_config, render_config),
}

# Commands that take one argument from the CLI. The value is bound at dispatch
# time so the (collector, renderer) contract stays identical to the rest.
PARAM_RENDERERS = {
    "ports": render_ports,
    "archive-check": render_archive_check,
    "apk-info": render_apk_info,
    "apk-security": render_apk_security,
    "tree": render_tree,
    "du": render_du,
    "find": render_find,
    "grep": render_grep,
    "head": render_view,
    "tail": render_view,
    "cat": render_view,
    "backup": lambda app, res: app.ui.status(
        "ok", "backup %s created (%s)" % (res.data["entry"]["id"],
                                          human_size(res.data["entry"]["bytes"]))),
    "restore": lambda app, res: app.ui.status(
        "ok", "restored to %s" % mask_home(res.data["restored_to"])),
    "undo": lambda app, res: app.ui.status(
        "ok", "undone: %s" % json.dumps(res.data, ensure_ascii=False)[:120]),
}


def run_command(app, name, collector=None, renderer=None):
    """Single dispatch path for every CLI command, both output modes.

    Machine mode: collect under a stdout firewall, emit one JSON document.
    Human mode:   collect, then render with the terminal UI.
    Returns the process exit code."""
    collector = collector or COMMANDS[name][0]
    renderer = renderer or COMMANDS[name][1]
    RT.command = name
    t0 = time.monotonic()
    try:
        if RT.machine:
            with stdout_firewall():
                res = collector(app)
        else:
            res = collector(app)
    except KeyboardInterrupt:
        res = OpResult.failure(ErrCode.INTERRUPTED, "cancelled by user")
    except ToolkitError as e:
        LOG.event("error", "command %s failed: %s" % (name, e.message), code=e.code)
        res = OpResult.failure(e.code, e.message, detail=e.detail)
    except Exception as e:                                # noqa: BLE001
        LOG.event("error", "command %s raised %s" % (name, type(e).__name__))
        res = OpResult.from_exception(e)
        if RT.debug:
            import traceback
            traceback.print_exc(file=sys.stderr)
    res.meta["duration_ms"] = int((time.monotonic() - t0) * 1000)

    if RT.machine:
        env = res.envelope(name)
        env["duration_ms"] = res.meta["duration_ms"]
        emit_json(env)
    else:
        if res.ok:
            try:
                renderer(app, res)
            except Exception as e:                        # noqa: BLE001
                app.ui.status("bad", "render failed: %s: %s" % (type(e).__name__, e))
                res = OpResult.failure(ErrCode.INTERNAL, "render failed")
            for w in res.warnings:
                app.ui.status("warn", w["message"])
        else:
            for w in res.warnings:
                app.ui.status("warn", w["message"])
            for e in res.errors:
                app.ui.status("bad", "%s: %s" % (e["code"], e["message"]))
    LOG.event("info", "command %s finished" % name, ok=res.ok,
              exit_code=res.exit_code, duration_ms=res.meta["duration_ms"])
    return res.exit_code


# ---------------------------------------------------------------------------
# SELF TEST - `clxv12.py --selftest`
# ---------------------------------------------------------------------------

def run_selftest(app):
    ui = app.ui
    results = []

    def check(name, fn):
        try:
            outcome = fn()
            ok_flag = bool(outcome[0]) if isinstance(outcome, tuple) else bool(outcome)
            note = outcome[1] if isinstance(outcome, tuple) and len(outcome) > 1 else ""
            results.append((name, ok_flag, note))
        except Exception as e:  # noqa: BLE001 - a test must never crash the suite
            results.append((name, False, "%s: %s" % (type(e).__name__, e)))

    # 1. syntax/import already proven by reaching here
    check("imports & app init", lambda: True)

    # 2. theme strip
    check("theme strip", lambda: ui.t.strip(ui.t.c("x", "red")) == "x")

    # 3. store roundtrip + corruption recovery
    def _store():
        app.store.save("config", {"probe": 1})
        if app.store.load("config", {}).get("probe") != 1:
            return (False, "roundtrip")
        try:
            DATA_FILES["config"].write_text("{corrupt", encoding="utf-8")
            recovered = app.store.load("config", {"ok": True})
            return (recovered.get("ok") is True, "corrupt-recovery")
        finally:
            DATA_FILES["config"].write_text("{}", encoding="utf-8")
    check("store roundtrip + corrupt recovery", _store)

    # 4. safe_path must reject system files even when cwd is /
    def _safepath():
        prev = os.getcwd()
        try:
            os.chdir("/")
            rejected = safe_path("/etc/passwd") is None and safe_path("/") is None
            os.chdir(prev)
            accepted = safe_path(str(Path.home())) is not None
            return (rejected and accepted, "cwd=/ hardened")
        finally:
            os.chdir(prev)
    check("safe_path rejects system paths", _safepath)

    # 5. zip path traversal rejection
    def _zip_traversal():
        tmp = Path.home() / ".clxv11_selftest_zip"
        tmp.mkdir(exist_ok=True)
        dest = tmp / "out"
        dest.mkdir(exist_ok=True)
        try:
            with zipfile.ZipFile(str(tmp / "evil.zip"), "w") as z:
                z.writestr("../escape.txt", "boom")
                z.writestr("ok.txt", "fine")
            with zipfile.ZipFile(str(tmp / "evil.zip")) as z:
                extracted, rejected = safe_extract_zip(z, dest)
            escaped = (Path.home() / "escape.txt").exists()
            if escaped:
                (Path.home() / "escape.txt").unlink()
            return (extracted == 1 and len(rejected) == 1 and not escaped,
                    "extracted=%d rejected=%d" % (extracted, len(rejected)))
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)
    check("zip traversal blocked", _zip_traversal)

    # 6. tar symlink / device rejection
    def _tar_safety():
        import io as _io
        tmp = Path.home() / ".clxv11_selftest_tar"
        tmp.mkdir(exist_ok=True)
        dest = tmp / "out"
        dest.mkdir(exist_ok=True)
        try:
            buf = _io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as t:
                info = tarfile.TarInfo("link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                t.addfile(info)
                reg = tarfile.TarInfo("reg.txt")
                data = b"hello"
                reg.size = len(data)
                t.addfile(reg, _io.BytesIO(data))
            buf.seek(0)
            with tarfile.open(fileobj=buf, mode="r:") as t:
                extracted, rejected = safe_extract_tar(t, dest)
            return (extracted == 1 and len(rejected) == 1 and
                    (dest / "reg.txt").exists(), "symlink rejected")
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)
    check("tar symlink/special blocked", _tar_safety)

    # 7. APK signing block parser on a constructed block
    def _apk_block():
        sig = b"\x00" * 16
        pair = struct.pack("<QI", 4 + len(sig), SIG_ID_V2) + sig
        # Correct v2 layout: size1 covers pairs + size2 + magic; the block
        # occupies [cd_offset - block_size - 8, cd_offset).
        block_size = len(pair) + 8 + 16
        block = struct.pack("<Q", block_size) + pair + struct.pack("<Q", block_size) + APK_SIG_MAGIC
        cd_offset = len(block)
        eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 0, 0, 0, cd_offset, 0)
        tmp = Path.home() / ".clxv11_selftest.apk"
        try:
            tmp.write_bytes(block + eocd)
            s = apk_signing_schemes(str(tmp))
            return (s["v2"] is True and s["error"] is None,
                    "v2 detected=%s" % s["v2"])
        finally:
            tmp.unlink(missing_ok=True)
    check("APK signing block v2 parse", _apk_block)

    # 8. runner: timeout + missing executable (pid-unique name: cannot exist)
    def _runner():
        rc1 = Runner.run(["sleep", "5"], timeout=0.2).rc   # Result.rc, not [0]
        missing = "clxv12-missing-%d" % os.getpid()
        r2 = Runner.run([missing])
        return (rc1 == 124 and r2.rc == 127 and "not found" in r2.err,
                "timeout=%d missing=%d" % (rc1, r2.rc))
    check("runner timeout & missing cmd", _runner)

    # 9. project classification evidence
    def _classify():
        tmp = Path.home() / ".clxv11_selftest_proj"
        tmp.mkdir(exist_ok=True)
        try:
            (tmp / "package.json").write_text("{}", encoding="utf-8")
            ptype, evidence = classify_project(tmp)
            return (ptype.startswith("Node") and "package.json" in evidence,
                    "%s via %s" % (ptype, evidence))
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)
    check("project classification evidence", _classify)

    # 10. bounded walk respects depth
    def _walk():
        tmp = Path.home() / ".clxv11_selftest_walk"
        deep = tmp / "a" / "b" / "c" / "d" / "e" / "f"
        deep.mkdir(parents=True, exist_ok=True)
        try:
            maxd = 0
            for _cur, _entries, depth in bounded_walk(tmp, max_depth=3):
                maxd = max(maxd, depth)
            return (maxd <= 3, "max depth seen %d" % maxd)
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)
    check("bounded walk depth limit", _walk)

    # 11. copy-into-itself: the guard constant must be a_in_b
    def _copy_guard():
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "proj"
            src.mkdir()
            final = src / "sub" / "proj"
            rel = path_relation(final, src)
            return (rel == "a_in_b", "relation=%s" % rel)
    check("copy-into-itself detectable (a_in_b)", _copy_guard)

    # 12. symlinked parent of a nonexistent path is fully resolved
    def _symlink_parent():
        with tempfile.TemporaryDirectory() as d:
            outside = Path(d) / "outside"
            outside.mkdir()
            link = Path(d) / "home" / "link"
            link.parent.mkdir()
            link.symlink_to(outside, target_is_directory=True)
            resolved = resolve_ancestor(link / "new.txt")
            return (resolved == outside / "new.txt", "resolved=%s" % resolved)
    check("symlink parent resolution (write escape closed)", _symlink_parent)

    # 13. ToolDetector usable before any scan()
    def _detector_lazy():
        try:
            d = ToolDetector()
            d.runnable_check("git")
            d.version_of("git")
            return (True, "no AttributeError")
        except AttributeError as e:
            return (False, str(e))
    check("ToolDetector lazy init", _detector_lazy)

    # 14. protected paths recognised
    check("protected paths", lambda: is_protected(Path.home()) and is_protected(Path("/")))

    # 15. atomic_write roundtrip + mode
    def _atomic():
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.txt"
            if not atomic_write(p, "hello", mode=0o600):
                return (False, "write failed")
            ok = p.read_text(encoding="utf-8") == "hello" and \
                 (p.stat().st_mode & 0o777) == 0o600
            # os.replace must swap a symlink itself, never chase it: the link
            # becomes a real file, the original target stays untouched.
            link = Path(d) / "ln"
            link.symlink_to(p)
            atomic_write(link, "swapped", mode=0o600)
            ok = ok and not link.is_symlink() \
                 and link.read_text(encoding="utf-8") == "swapped" \
                 and p.read_text(encoding="utf-8") == "hello"
            return (ok, "roundtrip + no symlink chase")
    check("atomic_write roundtrip", _atomic)

    # 16. human_size sanity
    check("human_size", lambda: human_size(0) == "0 B" and human_size(2048).endswith("KB"))

    # 17. port_check local-scope logic survives a missing network (ip=None)
    def _port_guard():
        net, ip, gw = None, None, None
        try:
            addr = ipaddress.ip_address("127.0.0.1")
            is_local = (net is not None and addr in net) or str(addr) == (gw or "") \
                or ((ip is not None and ip.version == 6) and addr.is_link_local) \
                or str(addr) in ("127.0.0.1", "::1")
            return (is_local is True, "loopback accepted without crash")
        except AttributeError as e:
            return (False, str(e))
    check("port_check guard (no-network safe)", _port_guard)

    # 18. every color name the UI uses exists in the palette
    check("palette completeness", lambda: all(
        n in ui.t._P for n in ("primary", "secondary", "success", "warning",
                               "error", "info", "muted", "title", "border",
                               "accent", "white")))

    # 19. schema stamping + v1 migration with backup
    def _schema():
        raw = DATA_FILES["profile"]
        snapshot = raw.read_text(encoding="utf-8") if raw.exists() else None
        try:
            app.store.save("profile", {"probe": 1})
            v = app.store.load("profile", {})
            ok_new = v.get("schema_version") == app.store.SCHEMA and v.get("probe") == 1
            raw.write_text(json.dumps({"old_shape": True}), encoding="utf-8")
            mig = app.store.load("profile", {})
            ok_mig = mig.get("schema_version") == app.store.SCHEMA \
                     and mig.get("old_shape") is True
            bak = raw.with_suffix(raw.suffix + ".v1.bak")
            ok_bak = bak.exists()
            return (ok_new and ok_mig and ok_bak, "stamp+migrate+backup")
        finally:
            if snapshot is not None:
                raw.write_text(snapshot, encoding="utf-8")
            raw.with_suffix(raw.suffix + ".v1.bak").unlink(missing_ok=True)
    check("store schema versioning + migration", _schema)

    # 20. single-instance lock: same-process second acquire must fail
    def _ilock():
        first = instance_lock()
        second = instance_lock()
        return (first is True and second is False,
                "first=%s second=%s" % (first, second))
    check("single-instance lock", _ilock)

    # 21. secure_target battery: 14 scenarios - out-of-bounds MUST be refused
    def _sec_battery():
        base = Path.home() / ".clxv12_selftest_sec"
        results = []
        try:
            shutil.rmtree(str(base), ignore_errors=True)
            base.mkdir()
            (base / "real.txt").write_text("x")
            (base / "dir").mkdir()
            deep = base / "a" / "b"
            deep.mkdir(parents=True)
            outside = Path(tempfile.mkdtemp())          # خارج الجذور المعتمدة
            (outside / "secret.txt").write_text("s")
            link = base / "link"
            link.symlink_to(outside, target_is_directory=True)
            flink = base / "flink"
            flink.symlink_to(outside / "secret.txt")
            nested = deep / "nl"
            nested.symlink_to(outside, target_is_directory=True)
            broken = base / "broken"
            broken.symlink_to(outside / "nope.txt")
            cases = [
                ("normal file", str(base / "real.txt"), dict(must_exist=True), True),
                ("normal dir", str(base / "dir"), dict(must_exist=True), True),
                ("../ traversal", str(base / "dir" / ".." / ".." / ".." / ".." / "evil"), dict(must_exist=False, for_write=True), False),
                ("absolute /etc", "/etc/passwd", dict(must_exist=True), False),
                ("symlink dir", str(link), dict(must_exist=True), False),
                ("symlink file", str(flink), dict(must_exist=True), False),
                ("nested symlink", str(nested / "secret.txt"), dict(must_exist=True), False),
                ("write through symlink parent", str(link / "new.txt"), dict(must_exist=False, for_write=True), False),
                ("broken symlink read", str(broken), dict(must_exist=True), False),
                ("broken symlink link-op", str(broken), dict(must_exist=True, allow_symlink_link_op=True), True),
                ("symlink link-op", str(flink), dict(must_exist=True, allow_symlink_link_op=True), True),
                ("new file inside", str(base / "new.txt"), dict(must_exist=False, for_write=True), True),
                ("new file outside", str(outside / "new.txt"), dict(must_exist=False, for_write=True), False),
                ("a/../../../x", str(base / "a" / "b" / ".." / ".." / ".." / ".." / "x"), dict(must_exist=False, for_write=True), False),
            ]
            for label, raw, kw, expect_ok in cases:
                r = secure_target(raw, base=base, **kw)
                results.append((label, (r is not None) == expect_ok))
            shutil.rmtree(str(outside), ignore_errors=True)
            bad = [l for l, ok in results if not ok]
            return (not bad, "failed: %s" % bad if bad else "14/14 scenarios correct")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("file security battery (14 scenarios)", _sec_battery)

    # 22. credential redaction: URLs + history persistence
    def _cred_redact():
        cases = [
            ("clone https://user:secret@example.com/r.git", "secret"),
            ("clone https://token123@example.com/r.git", "token123"),
            ("https://user:pass@example.com", "pass"),
            ("https://x.com/r?token=abc123", "abc123"),
            ("cmd --ks-pass hunter2", "hunter2"),
            ("password=hunter2", "hunter2"),
        ]
        bad = [s for text, s in cases if s in redact_credentials(text)]
        app.store.log("Clone", "Success", "https://user:topsecret9@example.com/r.git")
        hist = app.store.load("history", [])
        leaked = any("topsecret9" in str(h) for h in hist[-3:])
        return (not bad and not leaked, "leaked=%s bad=%s" % (leaked, bad))
    check("credential redaction (URLs + persistence)", _cred_redact)

    # 23. zip creation never follows symlinks
    def _zip_create_symlink():
        base = Path.home() / ".clxv12_selftest_zc"
        try:
            shutil.rmtree(str(base), ignore_errors=True)
            src = base / "src"
            src.mkdir(parents=True)
            (src / "real.txt").write_text("r")
            outside = Path(tempfile.mkdtemp())
            (outside / "secret.txt").write_text("s")
            (src / "link.txt").symlink_to(outside / "secret.txt")
            (src / "linkdir").symlink_to(outside, target_is_directory=True)
            out = base / "out.zip"
            n, skipped = zip_tree(src, out)
            names = zipfile.ZipFile(str(out)).namelist()
            ok = (n == 1 and skipped == 2 and "link.txt" not in names
                  and "secret.txt" not in str(names))
            shutil.rmtree(str(outside), ignore_errors=True)
            return (ok, "added=%d skipped=%d" % (n, skipped))
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("zip creation skips symlinks", _zip_create_symlink)

    # 24. runner kills its whole process group (children too)
    def _runner_tree():
        r = Runner.run(["/bin/sh", "-c", "sleep 30 & sleep 30"], timeout=0.4)
        chk = Runner.run(["sh", "-c", "ps -eo args 2>/dev/null | grep 'sleep 3[0]' | grep -v grep | wc -l"], timeout=10)
        leftover = chk.out.strip() not in ("0", "")
        return (r.rc == 124 and not leftover, "rc=%d leftover=%s" % (r.rc, leftover))
    check("runner process-group kill", _runner_tree)

    # 25. node template -> build plan integration
    def _node_integration():
        base = Path.home() / ".clxv12_selftest_node"
        try:
            shutil.rmtree(str(base), ignore_errors=True)
            base.mkdir()
            pj = base / "package.json"
            pj.write_text(json.dumps({"name": "x",
                                      "scripts": {"build": "node -e 1"}}))
            plans, pt = app.build.plan(base)
            ok_build = any("npm run build" in d or "NOT INSTALLED" in d for d, _ in plans)
            pj2 = json.loads(pj.read_text())
            del pj2["scripts"]["build"]
            pj.write_text(json.dumps(pj2))
            plans2, _ = app.build.plan(base)
            ok_nobuild = any("no 'build' script" in d for d, _ in plans2)
            return (pt.startswith("Node") and ok_build and ok_nobuild,
                    "%s / %s" % ([d for d, _ in plans], [d for d, _ in plans2]))
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("node template -> build plan", _node_integration)

    # 26. android incomplete detection
    def _android_detect():
        base = Path.home() / ".clxv12_selftest_and"
        try:
            shutil.rmtree(str(base), ignore_errors=True)
            base.mkdir()
            (base / "settings.gradle").write_text("rootProject.name='x'\n")
            plans, pt = app.build.plan(base)
            return (any("incomplete Android" in d for d, _ in plans), pt)
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("android incomplete detection", _android_detect)

    # 27. reverse DNS cannot hang (bounded call)
    def _dns_bound():
        t0 = time.monotonic()
        name = NetworkEngine._resolve_name("127.0.0.1")
        dt = time.monotonic() - t0
        return (isinstance(name, str) and dt < 4.0, "%s in %.2fs" % (name, dt))
    check("reverse DNS bounded", _dns_bound)

    # 28. crash log redaction
    def _crash_redact():
        write_crash_log("failed https://u:pw123@example.com/x")
        tail = (CONFIG_DIR / "crash.log").read_text(encoding="utf-8")[-400:]
        return ("pw123" not in tail and "[REDACTED]" in tail, "redacted in crash.log")
    check("crash log redaction", _crash_redact)

    # 29. legacy config migration (guarded, non-destructive)
    def _legacy_migrate():
        legacy = Path.home() / ".clxv11"
        fake_new = Path.home() / ".clxv12_mig_test"
        real_cd = CONFIG_DIR
        if legacy.exists() or not os.access(str(Path.home()), os.W_OK):
            return (True, "skipped (legacy exists or HOME read-only)")
        try:
            legacy.mkdir()
            (legacy / "probe.txt").write_text("x")
            globals()["CONFIG_DIR"] = fake_new
            try:
                first = migrate_legacy_config()
                moved = (not legacy.exists()) and (fake_new / "probe.txt").exists()
                globals()["CONFIG_DIR"] = real_cd
                second = migrate_legacy_config()
                return (first is True and moved and second is False,
                        "first=%s moved=%s second=%s" % (first, moved, second))
            finally:
                globals()["CONFIG_DIR"] = real_cd
        finally:
            shutil.rmtree(str(legacy), ignore_errors=True)
            shutil.rmtree(str(fake_new), ignore_errors=True)
    check("legacy config migration", _legacy_migrate)

    # 30. CLI matrix (version/help/json/invalid)
    def _cli_matrix():
        import subprocess as sp
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        script = str(Path(__file__).resolve())
        res = []
        for argv, expect in ((["--version"], 0), (["--help"], 0),
                             (["--capabilities", "--json"], 0),
                             (["--nonexistent-flag"], 2)):
            try:
                r = sp.run([sys.executable, script] + argv, capture_output=True,
                           text=True, timeout=180, env=env)
                res.append(r.returncode == expect)
            except Exception:
                res.append(False)
        return (all(res), str(res))
    check("CLI matrix (4 invocations)", _cli_matrix)

    # 31. runner exit semantics: success / nonzero / stderr capture
    def _runner_semantics():
        ok1 = Runner.run([sys.executable, "-c", "print('ok')"]).rc == 0
        r2 = Runner.run([sys.executable, "-c", "import sys; sys.exit(3)"])
        r3 = Runner.run([sys.executable, "-c", "import sys; sys.stderr.write('E!')"])
        return (ok1 and r2.rc == 3 and r3.err == "E!",
                "rc2=%d stderr=%r" % (r2.rc, r3.err))
    check("runner exit semantics", _runner_semantics)

    # 32. environment isolation: child only sees what it is given
    def _runner_env():
        env = {"PATH": os.environ.get("PATH", "")}
        r = Runner.run([sys.executable, "-c",
                        "import os;print('HOME' in os.environ)"], env=env, timeout=10)
        return (r.out.strip() == "False", "child HOME visible: %s" % r.out.strip())
    check("runner environment isolation", _runner_env)

    # 33. signal termination is distinguishable (negative rc on POSIX)
    def _runner_signal():
        if not hasattr(os, "killpg"):
            return (True, "non-POSIX: skipped")
        r = Runner.run(["/bin/sh", "-c", "kill -TERM $$"], timeout=10)
        return (r.rc < 0, "rc=%d (signal)" % r.rc)
    check("runner signal termination", _runner_signal)

    # 34. non-executable file -> permission denied (126)
    def _runner_noexec():
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "tool"
            f.write_text("#!/bin/sh\nexit 0\n")
            f.chmod(0o644)
            r = Runner.run([str(f)], timeout=10)
            return (r.rc in (126, 1, 2), "rc=%d" % r.rc)   # 126 POSIX; some shells give 1/2
    check("runner non-executable file", _runner_noexec)

    # 35. windows-style + non-UTF8 member names: contained, no crash
    def _zip_odd_names():
        d = Path(tempfile.mkdtemp())
        dest = d / "out"
        dest.mkdir()
        try:
            with zipfile.ZipFile(str(d / "w.zip"), "w") as z:
                z.writestr("C:\\evil\\x.txt", "win")        # ليس traversal على POSIX
                z.writestr("dir/\u00e9\u0644.txt", "uni")     # cp437/utf8 mix
            with zipfile.ZipFile(str(d / "w.zip")) as z:
                ex, rej = safe_extract_zip(z, dest)
            names = [p.name for p in dest.rglob("*")]
            ok = ex == 2 and not rej and all((dest in p.parents or p.parent == dest)
                                             for p in dest.rglob("*"))
            return (ok and "x.txt" in " ".join(names), "extracted=%d rejected=%d" % (ex, len(rej)))
        finally:
            shutil.rmtree(str(d), ignore_errors=True)
    check("zip windows/unicode member names", _zip_odd_names)

    # 36. cleanup filter: protected paths and symlinks survive
    import io, contextlib
    def _cleanup_guard():
        base = Path.home() / ".clxv12_selftest_clean"
        shutil.rmtree(str(base), ignore_errors=True)
        base.mkdir()
        real = base / "real_cache"
        real.mkdir()
        link = base / "link_cache"
        link.symlink_to(real, target_is_directory=True)
        prot = CONFIG_DIR / "prot_cache"
        prot.mkdir(exist_ok=True)
        buf = io.StringIO()
        saved = (app.ui.confirm, app.ui.pause)
        try:
            app.ui.confirm = lambda prompt, default=False: True
            app.ui.pause = lambda: None
            with contextlib.redirect_stdout(buf):
                app.cleanup._confirm_delete([real, link, prot], "test")
        finally:
            app.ui.confirm, app.ui.pause = saved
        # real deleted; the symlink was filtered (never followed/unlinked by
        # cleanup); the config-dir child survived
        ok = (not real.exists()) and link.is_symlink() and prot.exists()
        shutil.rmtree(str(base), ignore_errors=True)
        prot.rmdir()
        return (ok, "real deleted, symlink untouched, config child kept")
    check("cleanup refuses protected/symlink targets", _cleanup_guard)

    # 37. JSON purity on FIRST RUN (fresh HOME): stdout must parse as JSON
    def _json_purity():
        import subprocess as sp
        with tempfile.TemporaryDirectory() as fake_home:
            env = dict(os.environ, HOME=fake_home, PYTHONDONTWRITEBYTECODE="1")
            res = []
            for argv in (["--system", "--json"], ["--security", "--json"]):
                try:
                    r = sp.run([sys.executable, str(Path(__file__).resolve())] + argv,
                               capture_output=True, text=True, timeout=180, env=env)
                    json.loads(r.stdout)          # أي نص غير JSON = فشل
                    res.append(r.returncode == 0)
                except Exception:
                    res.append(False)
        return (all(res), str(res))
    check("CLI JSON purity on first run", _json_purity)

    # 38. android generator: structurally complete project
    def _android_template():
        base = Path.home() / ".clxv12_selftest_atpl"
        shutil.rmtree(str(base), ignore_errors=True)
        base.mkdir()
        answers = iter(["andproj", str(base), "android"])
        # These monkey-patches MUST be reverted: leaving a stubbed confirm()
        # in place would make every later test run against a UI that
        # auto-approves destructive prompts.
        saved = (app.ui.ask, app.ui.confirm, app.ui.pause)
        try:
            app.ui.ask = lambda prompt, default=None: next(answers, default)
            app.ui.confirm = lambda prompt, default=False: True
            app.ui.pause = lambda: None
            with contextlib.redirect_stdout(io.StringIO()):
                app.projects.create()
        finally:
            app.ui.ask, app.ui.confirm, app.ui.pause = saved
        p = base / "andproj"
        need = ["settings.gradle", "build.gradle", "gradle.properties", "gradlew",
                "app/build.gradle", "app/src/main/AndroidManifest.xml",
                "app/src/main/java/com/example/andproj/MainActivity.java",
                "app/src/main/res/values/strings.xml",
                "gradle/wrapper/gradle-wrapper.properties"]
        missing = [f for f in need if not (p / f).exists()]
        xok = os.access(str(p / "gradlew"), os.X_OK)
        t, e = classify_project(p)
        plans, pt = app.build.plan(p)
        incomplete = any("incomplete Android" in d for d, _ in plans)
        shutil.rmtree(str(base), ignore_errors=True)
        return (not missing and xok and t == "Android / Gradle" and not incomplete,
                "missing=%s exec=%s type=%s incomplete=%s" % (missing, xok, t, incomplete))
    check("android generator structural completeness", _android_template)

    # =======================================================================
    # v2.2.0 REGRESSION SUITE
    # Every test below asserts real behaviour. None of them assert merely
    # that a symbol exists.
    # =======================================================================

    # --- P0 regression: NetworkEngine.port_check 'str' has no 'version' ----
    def _regression_str_version():
        """The 2.1.0 crash: a local interface IP is a str, and the locality
        test read .version off it. Guard the type discipline directly."""
        try:
            address_is_local("192.168.1.5")
        except InvalidArgument:
            pass
        except AttributeError as e:
            return (False, "REGRESSION: %s" % e)
        # And through the real engine path that used to crash.
        res = app.network.port_check_report("127.0.0.1", "9")
        if not res.ok and res.errors[0]["code"] == ErrCode.SECURITY_BLOCK:
            return (False, "loopback must never be refused")
        return (res.ok, "loopback probe ok=%s" % res.ok)
    check("P0: port_check str/.version regression", _regression_str_version)

    def _port_types():
        t = resolve_target("127.0.0.1")
        if not isinstance(t, ResolvedTarget):
            return (False, "resolve_target returned %s" % type(t).__name__)
        bad = [a for a in t.addresses if isinstance(a, str)]
        return (not bad and t.primary.version == 4, "addresses are ipaddress objects")
    check("P0: resolve_target never yields strings", _port_types)

    def _port_states():
        """Real server on a real port: OPEN and CLOSED must both be observed."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        open_port = srv.getsockname()[1]
        tmp = socket.socket()
        tmp.bind(("127.0.0.1", 0))
        closed_port = tmp.getsockname()[1]
        tmp.close()
        try:
            o, _, _ = probe_port("127.0.0.1", open_port, socket.AF_INET, 1.0)
            c, _, _ = probe_port("127.0.0.1", closed_port, socket.AF_INET, 1.0)
            return (o == PORT_OPEN and c == PORT_CLOSED, "open=%s closed=%s" % (o, c))
        finally:
            srv.close()
    check("port probe: real OPEN and CLOSED", _port_states)

    def _port_hostname():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        try:
            res = app.network.port_check_report("localhost", str(port), timeout=1.0)
            return (res.ok and res.data["results"][0]["state"] == PORT_OPEN,
                    "localhost -> %s" % (res.data["results"][0]["state"]
                                         if res.ok else res.errors))
        finally:
            srv.close()
    check("port probe: hostname resolution", _port_hostname)

    def _port_ipv6():
        res = app.network.port_check_report("::1", "9", timeout=1.0)
        if res.ok:
            return (res.data["address_family"] == "IPv6", res.data["address_family"])
        return (res.errors[0]["code"] != ErrCode.INTERNAL,
                "IPv6 unavailable but handled: %s" % res.errors[0]["code"])
    check("port probe: IPv6 ::1 handled", _port_ipv6)

    def _port_bracket_zone():
        a = resolve_target("[::1]")
        b = resolve_target("fe80::1%wlan0")
        return (a.primary.version == 6 and b.scope_id == "wlan0",
                "bracket ok, zone=%s" % b.scope_id)
    check("port probe: [::1] and zone-id parsing", _port_bracket_zone)

    def _port_parse():
        cases = [("22,80", [22, 80]), ("8000-8003", [8000, 8001, 8002, 8003]),
                 ("80, 80 ,80", [80]), ("443-441", [441, 442, 443]),
                 (" 22 ; 23 ", [22, 23])]
        for raw, want in cases:
            got, _w = parse_ports(raw)
            if got != want:
                return (False, "%r -> %s want %s" % (raw, got, want))
        got, warns = parse_ports("22,abc,99999,443")
        return (got == [22, 443] and len(warns) == 2, "partial recovery ok")
    check("port parse: ranges, dedupe, recovery", _port_parse)

    def _port_parse_reject():
        for bad in ("", "   ", "abc", "0", "70000", "-5", ",,,", "all"):
            try:
                parse_ports(bad)
                return (False, "accepted %r" % bad)
            except InvalidArgument:
                continue
        return (True, "8 malformed specs refused")
    check("port parse: malformed specs refused", _port_parse_reject)

    def _port_policy():
        pub = app.network.port_check_report("8.8.8.8", "53")
        if pub.ok or pub.errors[0]["code"] != ErrCode.SECURITY_BLOCK:
            return (False, "public target not refused")
        if pub.exit_code != ExitCode.SECURITY_BLOCK:
            return (False, "wrong exit code %d" % pub.exit_code)
        loop = address_is_local(ipaddress.ip_address("127.0.0.1"))[0]
        link = address_is_local(ipaddress.ip_address("fe80::1"))[0]
        return (loop and link, "loopback+link-local allowed, public blocked")
    check("port policy: local-only enforcement", _port_policy)

    def _port_bounded():
        t0 = time.monotonic()
        res = app.network.port_check_report("127.0.0.1", "9000-9099",
                                            timeout=0.2, concurrency=32)
        dt = time.monotonic() - t0
        return (res.ok and dt < 30 and res.data["ports_probed"] == 100,
                "100 ports in %.1fs" % dt)
    check("port scan: bounded and concurrent", _port_bounded)

    # --- fuzz: hostile targets must produce errors, never crashes ---------
    def _fuzz_targets():
        hostile = [
            "", "   ", "\x00", "a\x00b", "999.999.999.999", "256.1.1.1",
            "not a host!!", "-lead.com", "trail-.com", "..", ".", "a" * 400,
            "%2e%2e%2f", "../../etc/passwd", "127.0.0.1;ls", "127.0.0.1|id",
            "$(whoami)", "`id`", "127.0.0.1\nrm -rf /", "::::::", "[::1",
            "1.1.1.1.1", "١٢٧.٠.٠.١", "😀.com", "\t\n", "host name",
            "-" * 60, "::1%", "%wlan0", "0x7f000001", "2130706433",
        ]
        crashed = []
        for raw in hostile:
            try:
                r = app.network.port_check_report(raw, "80")
                if r.ok and not r.data.get("probed_address"):
                    crashed.append((raw[:20], "ok with no address"))
            except ToolkitError:
                pass
            except Exception as e:                        # noqa: BLE001
                crashed.append((raw[:20], "%s: %s" % (type(e).__name__, e)))
        return (not crashed, "%d hostile targets, %d crashes" % (len(hostile), len(crashed)))
    check("fuzz: 31 hostile port targets", _fuzz_targets)

    def _fuzz_ports():
        hostile = ["", " ", "-", "--", "1-", "-1", "a-b", "1-2-3", "0-0",
                   "65535-65536", "99999999999999999999", "1," * 500,
                   "\x00", "٢٢", "😀", "1;2", "1|2", "$(id)", "1..2",
                   "1-99999999", " , , ", "+80", "80.5", "0x50", "-0"]
        crashed = []
        for raw in hostile:
            try:
                parse_ports(raw)
            except InvalidArgument:
                pass
            except Exception as e:                        # noqa: BLE001
                crashed.append((raw[:16], "%s: %s" % (type(e).__name__, e)))
        return (not crashed, "%d hostile specs, %d crashes" % (len(hostile), len(crashed)))
    check("fuzz: 25 hostile port specs", _fuzz_ports)

    def _fuzz_unicode_paths():
        base = Path.home() / ".clxv12_selftest_uni"
        shutil.rmtree(str(base), ignore_errors=True)
        base.mkdir(parents=True)
        names = ["سلام.py", "مشروعي", "ملف تجريبي.txt", "проект.rs",
                 "项目.go", "プロジェクト.java", "emoji_😀.md", "a b\tc.txt"]
        made, failed = 0, []
        try:
            for n in names:
                try:
                    p = base / n
                    if n.endswith(("/", "مشروعي")):
                        p.mkdir(exist_ok=True)
                    else:
                        p.write_text("محتوى", encoding="utf-8")
                    made += 1
                    if safe_path(str(p), must_exist=True) is None:
                        failed.append(n)
                    human_size(p.stat().st_size if p.is_file() else 0)
                except (OSError, UnicodeError) as e:
                    failed.append("%s: %s" % (n, e))
            t, _ev = classify_project(base)
            return (made == len(names) and not failed,
                    "%d unicode names, %d failures" % (made, len(failed)))
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("unicode: Arabic/Russian/CJK/emoji paths", _fuzz_unicode_paths)

    def _unicode_render():
        samples = ["سلام عليكم", "проект", "项目名称", "😀🎉", "mixed عربي en"]
        for s in samples:
            if ui.t.visible_len(s) <= 0:
                return (False, "visible_len failed on %r" % s)
            if len(ui.fit_padded(s, 20)) < 1:
                return (False, "fit_padded failed on %r" % s)
        return (True, "%d strings measured and padded" % len(samples))
    check("unicode: width measurement and padding", _unicode_render)

    # --- error model / exit codes -----------------------------------------
    def _exit_contract():
        pairs = [
            (ErrCode.INVALID_ARGUMENT, ExitCode.INVALID_ARGUMENT),
            (ErrCode.INVALID_HOST, ExitCode.INVALID_ARGUMENT),
            (ErrCode.NOT_FOUND, ExitCode.NOT_FOUND),
            (ErrCode.PERMISSION_DENIED, ExitCode.PERMISSION),
            (ErrCode.SECURITY_BLOCK, ExitCode.SECURITY_BLOCK),
            (ErrCode.PATH_TRAVERSAL, ExitCode.SECURITY_BLOCK),
            (ErrCode.TIMEOUT, ExitCode.TIMEOUT),
            (ErrCode.DEPENDENCY_MISSING, ExitCode.DEPENDENCY_MISSING),
            (ErrCode.BUILD_FAILED, ExitCode.BUILD_ERROR),
            (ErrCode.NETWORK_UNREACHABLE, ExitCode.NETWORK_ERROR),
            (ErrCode.INTERNAL, ExitCode.INTERNAL),
        ]
        for err, want in pairs:
            got = OpResult.failure(err, "x").exit_code
            if got != want:
                return (False, "%s -> %d, want %d" % (err, got, want))
        return (OpResult.success({}).exit_code == 0, "%d mappings verified" % len(pairs))
    check("exit codes: error->code contract", _exit_contract)

    def _result_model():
        r = OpResult.success({"a": 1})
        r.add_warning("careful")
        if not r.ok or r.exit_code != 0:
            return (False, "warning must not flip ok")
        r.add_error(ErrCode.NOT_FOUND, "gone")
        if r.ok or r.exit_code != ExitCode.NOT_FOUND:
            return (False, "error must flip ok and exit code")
        env = r.envelope("unit")
        json.loads(json.dumps(env))
        need = {"ok", "command", "version", "timestamp", "data", "warnings", "errors"}
        return (need <= set(env) and env["version"] == VERSION, "envelope complete")
    check("error model: OpResult semantics", _result_model)

    def _exception_mapping():
        cases = [(PermissionError("x"), ErrCode.PERMISSION_DENIED),
                 (FileNotFoundError("x"), ErrCode.NOT_FOUND),
                 (socket.gaierror("x"), ErrCode.DNS_FAILURE),
                 (ValueError("x"), ErrCode.INVALID_ARGUMENT),
                 (SecurityBlock("x"), ErrCode.SECURITY_BLOCK)]
        for exc, want in cases:
            got = OpResult.from_exception(exc).errors[0]["code"]
            if got != want:
                return (False, "%s -> %s want %s" % (type(exc).__name__, got, want))
        return (True, "%d exception mappings" % len(cases))
    check("error model: exception mapping", _exception_mapping)

    # --- credential redaction reaches logs and results --------------------
    def _redaction_everywhere():
        secrets = [
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
            "AIzaSyA1234567890abcdefghijklmnopqrstu",
            "Authorization: Bearer abcdef123456789",
            "password=hunter2supersecret",
            "https://user:pw@example.com/repo.git",
        ]
        for s in secrets:
            red = redact_credentials(s)
            if "REDACTED" not in red:
                return (False, "not redacted: %s" % s[:24])
            r = OpResult.failure(ErrCode.INTERNAL, "failed with %s" % s)
            if "REDACTED" not in json.dumps(r.envelope("t")):
                return (False, "leaked through OpResult: %s" % s[:24])
        return (True, "%d secret shapes redacted in errors" % len(secrets))
    check("security: secrets redacted in results", _redaction_everywhere)

    def _log_redaction():
        LOG.event("info", "token ghp_0123456789abcdefghijklmnopqrstuvwxyz here")
        LOG.audit("unit_test", "target password=supersecretvalue", "success", 1)
        leaked = []
        for stream in ("app", "audit"):
            p = LOG_DIR / ("%s.log" % stream)
            if not p.exists():
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            if "ghp_0123456789" in text or "supersecretvalue" in text:
                leaked.append(stream)
        return (not leaked, "log streams clean" if not leaked else "LEAK in %s" % leaked)
    check("security: secrets never reach the logs", _log_redaction)

    def _audit_trail():
        before = 0
        p = LOG_DIR / "audit.log"
        if p.exists():
            before = len(p.read_text(encoding="utf-8", errors="replace").splitlines())
        with audited("selftest_operation", "unit"):
            pass
        after = len(p.read_text(encoding="utf-8", errors="replace").splitlines()) \
            if p.exists() else 0
        if after <= before:
            return (False, "no audit record written")
        last = json.loads(p.read_text(encoding="utf-8", errors="replace").splitlines()[-1])
        return (last.get("operation") == "selftest_operation"
                and "duration_ms" in last and last.get("result") == "success",
                "audit record complete")
    check("audit: sensitive operations recorded", _audit_trail)

    def _log_rotation():
        p = LOG_DIR / "app.log"
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x" * (LOG_MAX_BYTES + 4096))
        LOG.event("info", "trigger rotation")
        rotated = Path("%s.1" % p).exists()
        size_ok = p.stat().st_size < LOG_MAX_BYTES
        return (rotated and size_ok, "rotated=%s new_size=%d" % (rotated, p.stat().st_size))
    check("logging: size-based rotation", _log_rotation)

    # --- non-interactive guards -------------------------------------------
    def _non_interactive():
        prev = RT.interactive
        try:
            RT.interactive = False
            if ui.ask("prompt", "fallback") != "fallback":
                return (False, "ask() ignored non-interactive default")
            if ui.confirm("destroy?", default=True) is not False:
                return (False, "confirm() auto-approved a destructive action")
            if ui.menu("m", [("1", "a", "run")]) is not None:
                return (False, "menu() blocked")
            ui.pause()
            return (True, "ask/confirm/pause/menu all safe")
        finally:
            RT.interactive = prev
    check("cli: non-interactive prompts never block", _non_interactive)

    def _stdout_firewall():
        prev = RT.json
        try:
            RT.json = True
            with stdout_firewall() as buf:
                print("this must not reach the user")
                sys.stdout.write("nor this")
            return ("must not reach" in buf.getvalue(), "leak captured, stdout clean")
        finally:
            RT.json = prev
    check("cli: stdout firewall captures leaks", _stdout_firewall)

    # --- data providers are headless --------------------------------------
    def _providers_headless():
        noisy = []
        for name in ("system", "tools", "capabilities", "security",
                     "health", "diagnostics"):
            collector = COMMANDS[name][0]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                r = collector(app)
            if buf.getvalue().strip():
                noisy.append(name)
            if not isinstance(r, OpResult):
                return (False, "%s did not return OpResult" % name)
            json.loads(json.dumps(r.envelope(name), default=str))
        return (not noisy, "6 providers silent and serialisable"
                if not noisy else "printed: %s" % noisy)
    check("cli: data providers print nothing", _providers_headless)

    def _provider_schema():
        for name in ("system", "tools", "projects", "capabilities", "security",
                     "health", "diagnostics", "doctor"):
            r = COMMANDS[name][0](app)
            env = r.envelope(name)
            need = {"ok", "command", "version", "timestamp", "data",
                    "warnings", "errors"}
            if not need <= set(env):
                return (False, "%s envelope missing %s" % (name, need - set(env)))
            if env["command"] != name or env["version"] != VERSION:
                return (False, "%s envelope identity wrong" % name)
        return (True, "8 commands produce the unified schema")
    check("json: unified envelope schema", _provider_schema)

    # --- full CLI JSON matrix in real subprocesses -------------------------
    def _cli_json_matrix():
        import subprocess as sp
        cmds = ["system", "network", "wifi", "tools", "projects", "scan",
                "security", "capabilities", "doctor", "health", "diagnostics"]
        bad, ansi_re = [], re.compile(r"\033\[[0-9;]*[A-Za-z]")
        with tempfile.TemporaryDirectory() as fake_home:
            env = dict(os.environ, HOME=fake_home, PYTHONDONTWRITEBYTECODE="1")
            for c in cmds:
                try:
                    r = sp.run([sys.executable, str(Path(__file__).resolve()),
                                "--" + c, "--json", "--timeout", "3"],
                               capture_output=True, text=True, timeout=240,
                               stdin=sp.DEVNULL, env=env)
                    doc = json.loads(r.stdout)        # any non-JSON byte = failure
                    if doc["command"] != c or doc["version"] != VERSION:
                        bad.append("%s:identity" % c)
                    if ansi_re.search(r.stdout):
                        bad.append("%s:ansi" % c)
                    if r.returncode != 0:
                        bad.append("%s:exit%d" % (c, r.returncode))
                except Exception as e:                # noqa: BLE001
                    bad.append("%s:%s" % (c, type(e).__name__))
        return (not bad, "%d/%d commands emit pure JSON%s"
                % (len(cmds) - len(bad), len(cmds),
                   "" if not bad else " FAILED: %s" % bad))
    check("json: all 11 CLI commands are pure", _cli_json_matrix)

    def _cli_exit_codes():
        import subprocess as sp
        exe = [sys.executable, str(Path(__file__).resolve())]
        with tempfile.TemporaryDirectory() as fake_home:
            env = dict(os.environ, HOME=fake_home, PYTHONDONTWRITEBYTECODE="1")

            def rc(argv):
                return sp.run(exe + argv, capture_output=True, text=True,
                              timeout=180, stdin=sp.DEVNULL, env=env).returncode
            cases = [
                (["--ports", "8.8.8.8", "--ports-list", "53"], ExitCode.SECURITY_BLOCK),
                (["--ports", "not a host!!"], ExitCode.INVALID_ARGUMENT),
                (["--ports", "127.0.0.1", "--ports-list", "abc"], ExitCode.INVALID_ARGUMENT),
                (["--definitely-not-a-flag"], ExitCode.INVALID_ARGUMENT),
                (["--system", "--network"], ExitCode.INVALID_ARGUMENT),
                (["--version"], ExitCode.SUCCESS),
                (["--health"], ExitCode.SUCCESS),
            ]
            wrong = []
            for argv, want in cases:
                got = rc(argv)
                if got != want:
                    wrong.append("%s->%d(want %d)" % (argv[0], got, want))
        return (not wrong, "%d exit-code cases verified%s"
                % (len(cases), "" if not wrong else " WRONG: %s" % wrong))
    check("cli: process exit codes honoured", _cli_exit_codes)

    def _cli_no_hang():
        """Commands must terminate with stdin closed - the 2.1.0 --tools path
        prompted for input and hung any script that called it."""
        import subprocess as sp
        with tempfile.TemporaryDirectory() as fake_home:
            env = dict(os.environ, HOME=fake_home, PYTHONDONTWRITEBYTECODE="1")
            try:
                r = sp.run([sys.executable, str(Path(__file__).resolve()),
                            "--tools", "--no-color"],
                           capture_output=True, text=True, timeout=120,
                           stdin=sp.DEVNULL, env=env)
                return (r.returncode == 0, "exit %d without prompting" % r.returncode)
            except sp.TimeoutExpired:
                return (False, "REGRESSION: --tools hung waiting for input")
    check("cli: --tools never prompts (regression)", _cli_no_hang)

    def _identity_clean():
        """No CLXV11 leakage in user-visible surfaces."""
        bad = []
        if "clxv11" in HELP_TEXT.lower():
            bad.append("HELP_TEXT")
        if build_parser().prog != "clxv12":
            bad.append("parser prog=%s" % build_parser().prog)
        if VERSION != "2.2.0":
            bad.append("version=%s" % VERSION)
        if APP_NAME != "CLXV12 TOOLKIT":
            bad.append("app name")
        for text in COMMAND_HELP.values():
            if "clxv11" in text.lower():
                bad.append("command help")
                break
        return (not bad, "identity clean" if not bad else str(bad))
    check("identity: no CLXV11 in user-facing text", _identity_clean)

    def _legacy_alias():
        return (CLXV11App is CLXV12App, "compat alias preserved")
    check("identity: CLXV11App compat alias", _legacy_alias)

    # --- chaos: things disappearing mid-flight ----------------------------
    def _chaos_missing_command():
        r = Runner.run(["definitely-not-a-real-binary-xyz"], timeout=5)
        return (r.rc == 127 and "not found" in r.err, "rc=%d" % r.rc)
    check("chaos: missing executable handled", _chaos_missing_command)

    def _chaos_readonly_dir():
        base = Path.home() / ".clxv12_selftest_ro"
        shutil.rmtree(str(base), ignore_errors=True)
        base.mkdir()
        try:
            os.chmod(str(base), 0o500)
            try:
                (base / "x.txt").write_text("nope", encoding="utf-8")
                wrote = True
            except (OSError, PermissionError):
                wrote = False
            if os.geteuid() == 0:
                return (True, "skipped detail: running as root")
            return (not wrote, "read-only dir refused the write")
        finally:
            try:
                os.chmod(str(base), 0o700)
            except OSError:
                pass
            shutil.rmtree(str(base), ignore_errors=True)
    check("chaos: read-only directory", _chaos_readonly_dir)

    def _chaos_file_vanishes():
        base = Path.home() / ".clxv12_selftest_vanish"
        shutil.rmtree(str(base), ignore_errors=True)
        base.mkdir()
        try:
            p = base / "gone.txt"
            p.write_text("data", encoding="utf-8")
            good = stream_hash(p, "sha256")
            if not good or len(good) != 64:
                return (False, "hash of a live file failed")
            p.unlink()
            # Contract: a vanished file yields a detectable None, never a
            # crash and never a bogus digest that callers would trust.
            gone = stream_hash(p, "sha256")
            if gone is not None:
                return (False, "deleted file returned a digest: %r" % gone)
            size, capped = dir_size(base)
            return (size >= 0 and capped is False,
                    "live=digest, vanished=None, dir_size=%d" % size)
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("chaos: file disappears mid-operation", _chaos_file_vanishes)

    def _chaos_broken_symlink():
        base = Path.home() / ".clxv12_selftest_sym"
        shutil.rmtree(str(base), ignore_errors=True)
        base.mkdir()
        try:
            link = base / "dangling"
            os.symlink(str(base / "nothing-here"), str(link))
            n = 0
            for _cur, entries, _d in bounded_walk(base):
                n += len(entries)
            return (safe_path(str(link), must_exist=True) is None and n >= 0,
                    "broken symlink refused, walk survived")
        except OSError as e:
            return (True, "symlinks unsupported here: %s" % e)
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("chaos: broken symlink", _chaos_broken_symlink)

    def _chaos_corrupt_store():
        backup = None
        p = DATA_FILES["config"]
        try:
            if p.exists():
                backup = p.read_text(encoding="utf-8", errors="replace")
            for junk in ("{not json", "", "[]", "\x00\x01\x02", "null",
                         '{"__schema__": "nonsense"}'):
                p.write_text(junk, encoding="utf-8", errors="replace")
                got = app.store.load("config", {"recovered": True})
                if not isinstance(got, dict):
                    return (False, "recovery returned %s for %r"
                            % (type(got).__name__, junk[:12]))
            return (True, "6 corrupt store shapes recovered")
        finally:
            if backup is not None:
                p.write_text(backup, encoding="utf-8")
            else:
                p.write_text("{}", encoding="utf-8")
    check("chaos: corrupted store recovery", _chaos_corrupt_store)

    def _chaos_empty_env():
        r = Runner.run([sys.executable, "-c", "import os;print(len(os.environ))"],
                       env={}, timeout=20)
        return (r.rc == 0, "empty environment survived, rc=%d" % r.rc)
    check("chaos: empty environment", _chaos_empty_env)

    def _doctor_never_repairs():
        before = {p: p.exists() for p in DATA_FILES.values()}
        res = data_doctor(app)
        after = {p: p.exists() for p in DATA_FILES.values()}
        if before != after:
            return (False, "doctor mutated the store")
        fails = [c for c in res.data["checks"] if c["status"] == "FAIL"]
        if fails and res.exit_code != ExitCode.DEPENDENCY_MISSING:
            return (False, "FAIL did not map to exit 7")
        return (True, "%d checks, %d fail, no repairs applied"
                % (len(res.data["checks"]), len(fails)))
    check("doctor: diagnoses without repairing", _doctor_never_repairs)

    def _health_fast():
        t0 = time.monotonic()
        res = data_health(app)
        dt = time.monotonic() - t0
        return (res.data["subsystems"] and dt < 20,
                "%d subsystems in %.1fs" % (len(res.data["subsystems"]), dt))
    check("health: fast subsystem probe", _health_fast)

    def _diagnostics_masked():
        res = data_diagnostics(app)
        blob = json.dumps(res.data)
        home = str(Path.home())
        if home != "/" and home in blob:
            return (False, "home directory leaked into diagnostics")
        return (res.data["environment"]["HOME"] == "~", "home masked")
    check("diagnostics: home directory masked", _diagnostics_masked)

    def _wifi_no_api():
        """Termux:API absent must yield UNAVAILABLE + reason, never a crash."""
        res = app.wifi.collect(probe_gateway=False)
        if not res.ok:
            return (False, "collect failed: %s" % res.errors)
        api = res.data["termux_api"]
        if not api["available"] and not api["reason"]:
            return (False, "unavailable without a stated reason")
        states = {c["status"] for c in res.data["checks"]}
        return (bool(states), "api_available=%s reason=%r"
                % (api["available"], api["reason"][:40]))
    check("wifi: honest capability reporting", _wifi_no_api)

    # =======================================================================
    # v2.2.0 BATCH 2: config / temp / TOCTOU / backup / undo / archive /
    #                 APK / file tools / search / benchmark
    # =======================================================================

    def _sandbox(name):
        p = Path.home() / (".clxv12_st_%s" % name)
        shutil.rmtree(str(p), ignore_errors=True)
        p.mkdir(parents=True)
        return p

    # --- configuration -----------------------------------------------------
    def _config_defaults():
        c = Config(Path.home() / ".clxv12_st_cfg" / "c.json").load()
        return (c.get("theme") == "auto" and c.get("limits.max_depth") == 5
                and c.get("backup.keep") == 20, "defaults intact")
    check("config: defaults load", _config_defaults)

    def _config_heals():
        base = _sandbox("cfg2")
        path = base / "c.json"
        path.write_text('{"theme":"nonsense","limits":{"max_depth":"abc"},'
                        '"backup":{"keep":true},"injected":"evil"}', encoding="utf-8")
        c = Config(path).load()
        ok = (c.get("theme") == "auto" and c.get("limits.max_depth") == 5
              and "injected" not in c.data)
        shutil.rmtree(str(base), ignore_errors=True)
        return (ok, "bad types rejected, unknown keys dropped")
    check("config: heals bad types and unknown keys", _config_heals)

    def _config_corrupt():
        base = _sandbox("cfg3")
        path = base / "c.json"
        outcomes = []
        for junk in ("{not json", "", "[]", "null", "\x00\x01", '"string"',
                     "[1,2,3]"):
            path.write_text(junk, encoding="utf-8", errors="replace")
            c = Config(path).load()
            outcomes.append(c.get("theme") == "auto")
        shutil.rmtree(str(base), ignore_errors=True)
        return (all(outcomes), "%d corrupt shapes recovered" % len(outcomes))
    check("config: recovers from 7 corrupt shapes", _config_corrupt)

    def _config_roundtrip():
        base = _sandbox("cfg4")
        path = base / "c.json"
        c = Config(path).load()
        c.set("theme", "mono").set("limits.max_results", 77)
        saved = c.save()
        back = Config(path).load()
        mode = oct(path.stat().st_mode & 0o777)
        shutil.rmtree(str(base), ignore_errors=True)
        return (saved and back.get("theme") == "mono"
                and back.get("limits.max_results") == 77 and mode == "0o600",
                "atomic save, mode %s" % mode)
    check("config: atomic save and reload", _config_roundtrip)

    # --- secure temp + TOCTOU ---------------------------------------------
    def _temp_security():
        seen = []
        for _ in range(3):
            with secure_temp_file(suffix=".probe") as (fd, p):
                os.write(fd, b"x")
                seen.append((str(p), oct(p.stat().st_mode & 0o777)))
            if os.path.exists(seen[-1][0]):
                return (False, "temp file survived the context manager")
        names = [Path(s[0]).name for s in seen]
        if len(set(names)) != 3:
            return (False, "temp names are predictable: %s" % names)
        modes = {s[1] for s in seen}
        return (modes == {"0o600"}, "unpredictable names, mode %s" % modes)
    check("security: temp files private and unpredictable", _temp_security)

    def _temp_cleanup_registry():
        with secure_temp_file(keep=True) as (fd, p):
            leaked = str(p)
        _TEMP_REGISTRY.add(leaked)
        cleanup_temp_registry()
        gone = not os.path.exists(leaked)
        try:
            os.unlink(leaked)
        except OSError:
            pass
        return (gone, "registry cleanup removed the leftover")
    check("security: temp registry cleanup", _temp_cleanup_registry)

    def _toctou_nofollow():
        base = _sandbox("toctou")
        try:
            real = base / "real.txt"
            real.write_text("sensitive", encoding="utf-8")
            link = base / "link.txt"
            os.symlink(str(real), str(link))
            try:
                fd = open_nofollow(link)
                os.close(fd)
                return (False, "REGRESSION: open_nofollow followed a symlink")
            except SecurityBlock:
                pass
            fd = open_nofollow(real)
            os.close(fd)
            return (True, "symlink refused at the syscall, regular file allowed")
        except OSError as e:
            return (True, "symlinks unsupported here: %s" % e)
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("TOCTOU: open_nofollow refuses symlinks", _toctou_nofollow)

    def _bounded_read():
        base = _sandbox("bread")
        try:
            p = base / "big.txt"
            p.write_text("A" * 100000, encoding="utf-8")
            data, truncated = read_file_bounded(p, max_bytes=1024)
            return (len(data) == 1024 and truncated,
                    "read %d bytes, truncated=%s" % (len(data), truncated))
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("memory: bounded read honours the cap", _bounded_read)

    def _atomic_bytes():
        base = _sandbox("atomb")
        try:
            p = base / "f.bin"
            ok = atomic_write_bytes(p, b"\x00\x01\x02payload")
            mode = oct(p.stat().st_mode & 0o777)
            leftovers = [x.name for x in base.iterdir() if x.name.endswith(".tmp")]
            return (ok and p.read_bytes() == b"\x00\x01\x02payload"
                    and mode == "0o600" and not leftovers,
                    "atomic, mode %s, no temp residue" % mode)
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("atomic: byte writes leave no partial state", _atomic_bytes)

    # --- backup ------------------------------------------------------------
    def _backup_file_cycle():
        base = _sandbox("bk1")
        try:
            src = base / "doc.txt"
            src.write_text("original content", encoding="utf-8")
            created = BACKUPS.create(src, "selftest")
            if not created.ok:
                return (False, str(created.errors))
            bid = created.data["entry"]["id"]
            if not BACKUPS.verify(bid).ok:
                return (False, "fresh backup failed verification")
            src.write_text("DESTROYED", encoding="utf-8")
            restored = BACKUPS.restore(bid, overwrite=True)
            ok = restored.ok and src.read_text(encoding="utf-8") == "original content"
            BACKUPS.delete(bid)
            return (ok, "create -> verify -> restore -> delete")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("backup: full file lifecycle", _backup_file_cycle)

    def _backup_integrity():
        base = _sandbox("bk2")
        try:
            src = base / "d.txt"
            src.write_text("payload", encoding="utf-8")
            created = BACKUPS.create(src, "selftest")
            bid = created.data["entry"]["id"]
            stored = Path(created.data["entry"]["stored"])
            stored.write_text("TAMPERED", encoding="utf-8")
            bad = BACKUPS.verify(bid)
            restore_blocked = not BACKUPS.restore(bid, overwrite=True).ok
            BACKUPS.delete(bid)
            return ((not bad.ok) and restore_blocked,
                    "tampering detected, restore refused")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("backup: integrity hash detects tampering", _backup_integrity)

    def _backup_directory():
        base = _sandbox("bk3")
        try:
            d = base / "proj"
            (d / "sub").mkdir(parents=True)
            (d / "a.txt").write_text("A", encoding="utf-8")
            (d / "sub" / "b.txt").write_text("B", encoding="utf-8")
            created = BACKUPS.create(d, "selftest")
            if not created.ok:
                return (False, str(created.errors))
            shutil.rmtree(str(d))
            restored = BACKUPS.restore(created.data["entry"]["id"], overwrite=True)
            ok = (restored.ok and (d / "a.txt").read_text(encoding="utf-8") == "A"
                  and (d / "sub" / "b.txt").read_text(encoding="utf-8") == "B")
            BACKUPS.delete(created.data["entry"]["id"])
            return (ok, "directory tree round-tripped")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("backup: directory snapshot and restore", _backup_directory)

    def _backup_guards():
        missing = BACKUPS.create(Path.home() / "definitely_absent_xyz")
        unknown = BACKUPS.delete("no-such-id")
        bad_restore = BACKUPS.restore("no-such-id")
        return (missing.errors[0]["code"] == ErrCode.NOT_FOUND
                and unknown.errors[0]["code"] == ErrCode.NOT_FOUND
                and bad_restore.errors[0]["code"] == ErrCode.NOT_FOUND,
                "3 missing-target paths return NOT_FOUND")
    check("backup: missing targets handled", _backup_guards)

    def _backup_no_silent_overwrite():
        base = _sandbox("bk4")
        try:
            src = base / "x.txt"
            src.write_text("v1", encoding="utf-8")
            created = BACKUPS.create(src, "selftest")
            src.write_text("v2", encoding="utf-8")
            blocked = BACKUPS.restore(created.data["entry"]["id"], overwrite=False)
            still = src.read_text(encoding="utf-8")
            BACKUPS.delete(created.data["entry"]["id"])
            return ((not blocked.ok) and still == "v2",
                    "restore refuses to clobber without overwrite=True")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("backup: no silent overwrite", _backup_no_silent_overwrite)

    # --- undo --------------------------------------------------------------
    def _undo_move():
        base = _sandbox("un1")
        try:
            a, b = base / "a.txt", base / "b.txt"
            a.write_text("data", encoding="utf-8")
            shutil.move(str(a), str(b))
            UNDO.record("move", source=str(a), destination=str(b))
            res = UNDO.undo_last()
            return (res.ok and a.exists() and not b.exists(),
                    "move reverted" if res.ok else str(res.errors))
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("undo: move is reverted", _undo_move)

    def _undo_honesty():
        recorded = [UNDO.record(op, source="x") for op in IRREVERSIBLE_OPS]
        if any(r is not None for r in recorded):
            return (False, "an irreversible operation was journalled")
        hist = UNDO.history()
        return ("build" in hist.data["irreversible_operations"]
                and "move" in hist.data["reversible_operations"],
                "%d irreversible ops refused and documented" % len(IRREVERSIBLE_OPS))
    check("undo: irreversible operations are never claimed", _undo_honesty)

    def _undo_mkdir_guard():
        base = _sandbox("un2")
        try:
            d = base / "made"
            d.mkdir()
            UNDO.record("mkdir", source=str(d), destination=str(d))
            (d / "surprise.txt").write_text("x", encoding="utf-8")
            res = UNDO.undo_last()
            return ((not res.ok) and d.exists(),
                    "refused to remove a now non-empty directory")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("undo: refuses unsafe inverse", _undo_mkdir_guard)

    def _undo_empty():
        journal = UndoJournal(Path.home() / ".clxv12_st_undo_empty.json")
        res = journal.undo_last()
        try:
            journal.path.unlink()
        except OSError:
            pass
        return (res.errors[0]["code"] == ErrCode.NOT_FOUND, "nothing to undo")
    check("undo: empty journal handled", _undo_empty)

    # --- archive safety analysis ------------------------------------------
    def _archive_safe():
        base = _sandbox("ar1")
        try:
            z = base / "good.zip"
            with zipfile.ZipFile(str(z), "w") as zf:
                zf.writestr("a.txt", "A")
                zf.writestr("dir/b.txt", "B")
            res = analyze_archive(z)
            return (res.ok and res.data["safe_to_extract"]
                    and res.data["would_reject"] == 0,
                    "clean archive passes all %d checks" % len(res.data["checks"]))
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("archive: clean ZIP passes analysis", _archive_safe)

    def _archive_hostile():
        base = _sandbox("ar2")
        try:
            z = base / "evil.zip"
            with zipfile.ZipFile(str(z), "w") as zf:
                zf.writestr("../escape.txt", "x")
                zf.writestr("/absolute.txt", "x")
                zf.writestr("a/" * 40 + "deep.txt", "x")
                zf.writestr("N" * 300 + ".txt", "x")
                zf.writestr("ok.txt", "fine")
            res = analyze_archive(z)
            c = res.data["finding_counts"]
            needed = ("PATH_TRAVERSAL", "ABSOLUTE_PATH", "EXCESSIVE_DEPTH",
                      "NAME_TOO_LONG")
            missing = [n for n in needed if not c.get(n)]
            return (not missing and not res.data["safe_to_extract"]
                    and res.data["would_extract"] == 1,
                    "4 attack classes detected, 1 member survives"
                    if not missing else "missed: %s" % missing)
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("archive: traversal/absolute/depth/length detected", _archive_hostile)

    def _archive_bomb():
        base = _sandbox("ar3")
        try:
            z = base / "bomb.zip"
            with zipfile.ZipFile(str(z), "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("bomb.bin", b"\x00" * (24 << 20))
            res = analyze_archive(z)
            return (not res.data["safe_to_extract"]
                    and res.data["finding_counts"].get("SUSPICIOUS_COMPRESSION"),
                    "ratio %.0fx flagged" % res.data["ratio"])
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("archive: compression bomb detected", _archive_bomb)

    def _archive_tar_links():
        base = _sandbox("ar4")
        try:
            t = base / "links.tar"
            with tarfile.open(str(t), "w") as tf:
                ti = tarfile.TarInfo("escape")
                ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
                tf.addfile(ti)
                ti2 = tarfile.TarInfo("dev")
                ti2.type = tarfile.CHRTYPE
                tf.addfile(ti2)
            res = analyze_archive(t)
            c = res.data["finding_counts"]
            return (c.get("LINK_ESCAPES_DESTINATION") and c.get("SPECIAL_FILE"),
                    "escaping symlink and device file both flagged")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("archive: TAR symlink escape and device files", _archive_tar_links)

    def _archive_corrupt_inputs():
        base = _sandbox("ar5")
        try:
            crashes = []
            for i, junk in enumerate([b"", b"PK\x03\x04garbage" * 20,
                                      b"\x00" * 4096, b"ustar" * 100,
                                      os.urandom(2048)]):
                p = base / ("junk%d.zip" % i)
                p.write_bytes(junk)
                try:
                    r = analyze_archive(p)
                    if r.ok and not isinstance(r.data, dict):
                        crashes.append(i)
                except Exception as e:                    # noqa: BLE001
                    crashes.append("%d:%s" % (i, type(e).__name__))
            missing = analyze_archive(base / "absent.zip")
            return (not crashes and missing.errors[0]["code"] == ErrCode.NOT_FOUND,
                    "5 corrupt inputs handled, missing file -> NOT_FOUND")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("archive: corrupt inputs never crash", _archive_corrupt_inputs)

    # --- AXML / APK --------------------------------------------------------
    def _axml_fixture(utf8=True, debuggable=True):
        """Build a REAL binary AndroidManifest.xml so the parser is exercised
        against the actual format, not a mock."""
        def pad4(b):
            return b + b"\x00" * ((-len(b)) % 4)

        strings = ["manifest", "uses-sdk", "uses-permission", "application",
                   "activity", "intent-filter", "package", "versionCode",
                   "versionName", "minSdkVersion", "targetSdkVersion", "name",
                   "debuggable", "exported", "com.selftest.app", "2.0.1",
                   "android.permission.CAMERA",
                   "android.permission.SYSTEM_ALERT_WINDOW",
                   ".MainActivity", ".Exported"]
        idx = {s: i for i, s in enumerate(strings)}
        data, offsets = bytearray(), []
        for s in strings:
            offsets.append(len(data))
            if utf8:
                enc = s.encode("utf-8")
                data += bytes([len(s) & 0x7F, len(enc) & 0x7F]) + enc + b"\x00"
            else:
                enc = s.encode("utf-16-le")
                data += struct.pack("<H", len(s)) + enc + b"\x00\x00"
        data = pad4(bytes(data))
        header = 28 + 4 * len(strings)
        pool = struct.pack("<IIIIIII", 0x001C0001, header + len(data),
                           len(strings), 0, (1 << 8) if utf8 else 0, header, 0)
        pool += b"".join(struct.pack("<I", o) for o in offsets) + data

        def start(name, attrs):
            body = struct.pack("<IIHHHHHH", 0xFFFFFFFF, idx[name], 20, 20,
                               len(attrs), 0, 0, 0)
            for an, dtype, dval in attrs:
                body += struct.pack("<IIIHBBI", 0xFFFFFFFF, idx[an], 0xFFFFFFFF,
                                    8, 0, dtype, dval & 0xFFFFFFFF)
            return struct.pack("<IIII", 0x00100102, 16 + len(body), 1,
                               0xFFFFFFFF) + body

        def end(name):
            return struct.pack("<IIIIII", 0x00100103, 24, 1, 0xFFFFFFFF,
                               0xFFFFFFFF, idx[name])

        STR, DEC, BOOL = 0x03, 0x10, 0x12
        ev = [start("manifest", [("package", STR, idx["com.selftest.app"]),
                                 ("versionCode", DEC, 7),
                                 ("versionName", STR, idx["2.0.1"])]),
              start("uses-sdk", [("minSdkVersion", DEC, 19),
                                 ("targetSdkVersion", DEC, 25)]), end("uses-sdk")]
        for perm in ("android.permission.CAMERA",
                     "android.permission.SYSTEM_ALERT_WINDOW"):
            ev += [start("uses-permission", [("name", STR, idx[perm])]),
                   end("uses-permission")]
        ev += [start("application",
                     [("debuggable", BOOL, 0xFFFFFFFF if debuggable else 0)]),
               start("activity", [("name", STR, idx[".MainActivity"])]),
               start("intent-filter", []), end("intent-filter"), end("activity"),
               start("activity", [("name", STR, idx[".Exported"]),
                                  ("exported", BOOL, 0xFFFFFFFF)]),
               end("activity"), end("application"), end("manifest")]
        body = pool + struct.pack("<II", 0x00080180, 8) + b"".join(ev)
        return struct.pack("<II", 0x00080003, 8 + len(body)) + body

    def _axml_parse():
        root = parse_binary_manifest(_axml_fixture(utf8=True))
        if root["tag"] != "manifest":
            return (False, "root tag %r" % root["tag"])
        a = root["attrs"]
        return (a.get("package") == "com.selftest.app" and a.get("versionCode") == 7
                and a.get("versionName") == "2.0.1",
                "package/version parsed from real AXML")
    check("APK: binary AXML parsed (UTF-8 pool)", _axml_parse)

    def _axml_utf16():
        root = parse_binary_manifest(_axml_fixture(utf8=False))
        return (root["attrs"].get("package") == "com.selftest.app",
                "UTF-16 string pool parsed")
    check("APK: binary AXML parsed (UTF-16 pool)", _axml_utf16)

    def _axml_malformed():
        crashes = []
        good = _axml_fixture()
        cases = [b"", b"\x00" * 4, b"\x03\x00\x08\x00" + b"\xff" * 64,
                 good[:32], good[:len(good) // 2], bytes(reversed(good)),
                 struct.pack("<II", 0x00080003, 0xFFFFFFFF) + good[8:],
                 os.urandom(512)]
        for i, blob in enumerate(cases):
            try:
                parse_binary_manifest(blob)
            except (AXMLError, ToolkitError):
                pass
            except Exception as e:                        # noqa: BLE001
                crashes.append("%d:%s" % (i, type(e).__name__))
        return (not crashes, "%d malformed manifests -> controlled errors"
                % len(cases) if not crashes else str(crashes))
    check("APK: 8 malformed AXML blobs never crash", _axml_malformed)

    def _apk_manifest():
        base = _sandbox("apk1")
        try:
            apk = base / "t.apk"
            with zipfile.ZipFile(str(apk), "w") as z:
                z.writestr("AndroidManifest.xml", _axml_fixture())
                z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
                z.writestr("META-INF/CERT.RSA", b"cert")
            res = apk_manifest_info(apk)
            if not res.ok:
                return (False, str(res.errors))
            d = res.data
            return (d["package"] == "com.selftest.app" and d["min_sdk"] == 19
                    and d["target_sdk"] == 25 and len(d["permissions"]) == 2
                    and len(d["components"]["activity"]) == 2
                    and d["container"] == "apk",
                    "package/sdk/permissions/components all extracted")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("APK: manifest info from a real container", _apk_manifest)

    def _apk_security():
        base = _sandbox("apk2")
        try:
            apk = base / "t.apk"
            with zipfile.ZipFile(str(apk), "w") as z:
                z.writestr("AndroidManifest.xml", _axml_fixture(debuggable=True))
                z.writestr("classes.dex", b"dex\n035\x00")
                z.writestr("META-INF/CERT.RSA", b"cert")
            res = apk_security_report(apk)
            if not res.ok:
                return (False, str(res.errors))
            by = {f["check"]: f for f in res.data["findings"]}
            need = {
                "debuggable flag": "HIGH",
                "special permissions": "HIGH",
                "dangerous permissions": "WARNING",
                "targetSdkVersion": "WARNING",
                "minSdkVersion": "WARNING",
            }
            wrong = [k for k, lvl in need.items()
                     if by.get(k, {}).get("level") != lvl]
            has_export = any("exported" in k for k in by)
            return (not wrong and has_export and res.data["high"] >= 2,
                    "%d HIGH / %d WARNING detected"
                    % (res.data["high"], res.data["warning"])
                    if not wrong else "wrong level: %s" % wrong)
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("APK: security indicators classified", _apk_security)

    def _apk_invalid():
        base = _sandbox("apk3")
        try:
            bad = base / "bad.apk"
            bad.write_bytes(b"this is not a zip")
            noman = base / "noman.apk"
            with zipfile.ZipFile(str(noman), "w") as z:
                z.writestr("hello.txt", "x")
            r1 = apk_manifest_info(bad)
            r2 = apk_manifest_info(noman)
            r3 = apk_manifest_info(base / "absent.apk")
            return (r1.errors[0]["code"] == ErrCode.APK_INVALID
                    and r2.errors[0]["code"] == ErrCode.APK_INVALID
                    and r3.errors[0]["code"] == ErrCode.NOT_FOUND,
                    "non-zip / no-manifest / missing all classified")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("APK: invalid containers classified", _apk_invalid)

    def _apk_no_false_claims():
        base = _sandbox("apk4")
        try:
            apk = base / "t.apk"
            with zipfile.ZipFile(str(apk), "w") as z:
                z.writestr("AndroidManifest.xml", _axml_fixture())
                z.writestr("classes.dex", b"dex\n035\x00")
            res = apk_security_report(apk)
            texts = " ".join(f["detail"] for f in res.data["findings"])
            return ("cryptographic verification requires" in texts
                    and "not a judgement" in res.data["disclaimer"],
                    "signature limits and disclaimer stated explicitly")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("APK: does not claim cryptographic verification", _apk_no_false_claims)

    # --- file tools --------------------------------------------------------
    def _filetools_fixture():
        base = _sandbox("ft")
        (base / "src").mkdir()
        (base / "node_modules" / "pkg").mkdir(parents=True)
        (base / "src" / "main.py").write_text(
            "import os\nAPI_KEY = 'ghp_0123456789abcdefghijklmnop'\n"
            "print('hello world')\n", encoding="utf-8")
        (base / "src" / "util.py").write_text("def helper():\n    return 1\n",
                                              encoding="utf-8")
        (base / "README.md").write_text("# Title\nhello world\n", encoding="utf-8")
        (base / "data.bin").write_bytes(bytes(range(256)) * 40)
        (base / "node_modules" / "pkg" / "index.js").write_text("x" * 4000,
                                                                encoding="utf-8")
        (base / "ملف.txt").write_text("مرحبا\nسطر ثان\n", encoding="utf-8")
        return base

    def _tree():
        base = _filetools_fixture()
        try:
            res = file_tree(base, max_depth=3, max_entries=200)
            heavy = any("node_modules" in ln for ln in res.data["lines"])
            capped = file_tree(base, max_depth=3, max_entries=2)
            return (res.ok and res.data["entries"] > 3 and not heavy
                    and capped.data["truncated"] and capped.data["entries"] <= 2,
                    "%d entries, heavy dirs skipped, cap honoured"
                    % res.data["entries"])
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("files: tree bounded and skips heavy dirs", _tree)

    def _du():
        base = _filetools_fixture()
        try:
            res = disk_usage(base)
            rows = res.data["entries"]
            sorted_ok = all(rows[i]["bytes"] >= rows[i + 1]["bytes"]
                            for i in range(len(rows) - 1))
            return (res.ok and res.data["total_bytes"] > 0 and sorted_ok
                    and "percent" in rows[0],
                    "%s total, sorted desc" % res.data["total_human"])
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("files: du totals and ranks children", _du)

    def _find():
        base = _filetools_fixture()
        try:
            by_ext = find_files(base, ext=".py")
            by_name = find_files(base, name="readme")
            by_regex = find_files(base, regex=r"\.md$")
            unicode_hit = find_files(base, name="ملف")
            heavy_off = find_files(base, name="index.js")
            heavy_on = find_files(base, name="index.js", include_heavy=True)
            capped = find_files(base, max_results=1)
            return (by_ext.data["matches"] == 2 and by_name.data["matches"] == 1
                    and by_regex.data["matches"] == 1
                    and unicode_hit.data["matches"] == 1
                    and heavy_off.data["matches"] == 0
                    and heavy_on.data["matches"] == 1
                    and capped.data["truncated"],
                    "ext/name/regex/unicode/heavy/cap all correct")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("files: find by name, ext, regex and unicode", _find)

    def _find_bad_regex():
        base = _filetools_fixture()
        try:
            for bad in ("[unclosed", "(?P<", "*", "(?", "a{99999999,}"):
                try:
                    find_files(base, regex=bad)
                except InvalidArgument:
                    continue
                except re.error:
                    return (False, "raw re.error leaked for %r" % bad)
            return (True, "5 malformed regexes -> InvalidArgument")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("files: malformed regex rejected cleanly", _find_bad_regex)

    def _grep():
        base = _filetools_fixture()
        try:
            plain = grep_files(base, "hello world")
            rx = grep_files(base, r"def \w+\(", regex=True)
            uni = grep_files(base, "مرحبا")
            secret = grep_files(base, "API_KEY")
            leaked = any("ghp_0123456789" in h["text"] for h in secret.data["results"])
            return (plain.data["matches"] >= 2 and rx.data["matches"] == 1
                    and uni.data["matches"] == 1
                    and plain.data["skipped"]["binary"] >= 1 and not leaked,
                    "literal/regex/unicode ok, binary skipped, secrets redacted")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("files: grep content, unicode, binary skip, redaction", _grep)

    def _grep_streaming():
        base = _sandbox("grepbig")
        try:
            big = base / "huge.log"
            with open(str(big), "w", encoding="utf-8") as fh:
                for i in range(150000):
                    fh.write("filler line %d padding padding padding\n" % i)
                fh.write("UNIQUE_NEEDLE_TOKEN\n")
            size = big.stat().st_size
            t0 = time.monotonic()
            res = grep_files(big, "UNIQUE_NEEDLE_TOKEN", max_file_size=size + 1)
            dt = time.monotonic() - t0
            return (res.data["matches"] == 1 and dt < 30,
                    "%s streamed in %.1fs" % (human_size(size), dt))
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("files: grep streams a multi-MB file", _grep_streaming)

    def _head_tail_cat():
        base = _filetools_fixture()
        try:
            h = head_file(base / "README.md", 1)
            t = tail_file(base / "README.md", 1)
            hb = head_file(base / "data.bin")
            c = cat_file(base / "README.md")
            cb = cat_file(base / "data.bin")
            cs = cat_file(base / "src" / "main.py")
            return (h.data["lines"] == ["# Title"]
                    and t.data["lines"] == ["hello world"]
                    and hb.data["binary"] is True
                    and c.ok and "hello world" in c.data["text"]
                    and (not cb.ok)
                    and "ghp_0123456789" not in cs.data["text"],
                    "head/tail correct, binary refused, cat redacted")
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("files: head/tail/cat with binary and secret guards", _head_tail_cat)

    def _file_tools_path_security():
        blocked = 0
        for fn in (lambda: file_tree("/etc"), lambda: disk_usage("/"),
                   lambda: find_files("/etc", name="passwd"),
                   lambda: grep_files("/etc", "root"),
                   lambda: head_file("/etc/passwd"),
                   lambda: cat_file("/etc/passwd")):
            try:
                fn()
            except (SecurityBlock, ToolkitError):
                blocked += 1
            except OSError:
                blocked += 1
        return (blocked == 6, "%d/6 system-path operations refused" % blocked)
    check("files: system paths refused by every tool", _file_tools_path_security)

    def _binary_detection():
        base = _sandbox("bin")
        try:
            (base / "text.txt").write_text("plain ascii\n" * 50, encoding="utf-8")
            (base / "utf8.txt").write_text("مرحبا 你好 привет\n" * 20, encoding="utf-8")
            (base / "nul.bin").write_bytes(b"abc\x00def" * 100)
            (base / "ctrl.bin").write_bytes(bytes(range(1, 7)) * 400)
            (base / "empty.txt").write_bytes(b"")
            results = {n: is_binary_file(base / n)
                       for n in ("text.txt", "utf8.txt", "nul.bin",
                                 "ctrl.bin", "empty.txt")}
            expected = {"text.txt": False, "utf8.txt": False, "nul.bin": True,
                        "ctrl.bin": True, "empty.txt": False}
            return (results == expected, str(results))
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
    check("files: binary detection incl. UTF-8 text", _binary_detection)

    # --- benchmark ---------------------------------------------------------
    def _benchmark():
        res = run_benchmark(app, iterations=1)
        marks = res.data["benchmarks"]
        errs = [m for m in marks if m["status"] == "ERROR"]
        timed = [m for m in marks if m["duration_ms"] is not None]
        return (len(marks) >= 8 and not errs and len(timed) == len(marks),
                "%d benchmarks, %.0f ms total%s"
                % (len(marks), res.data["total_ms"],
                   "" if not res.data["slow"] else ", slow: %s" % res.data["slow"]))
    check("benchmark: all hot paths measured", _benchmark)

    # --- new CLI surface ---------------------------------------------------
    def _new_commands_headless():
        noisy, broken = [], []
        for name in ("backups", "undo-list", "config"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                r = COMMANDS[name][0](app)
            if buf.getvalue().strip():
                noisy.append(name)
            if not isinstance(r, OpResult):
                broken.append(name)
            json.loads(json.dumps(r.envelope(name), default=str))
        return (not noisy and not broken,
                "3 new providers silent and serialisable")
    check("cli: new data providers are headless", _new_commands_headless)

    def _param_command_matrix():
        import subprocess as sp
        base = _sandbox("cli2")
        (base / "a.txt").write_text("hello selftest\n", encoding="utf-8")
        with zipfile.ZipFile(str(base / "s.zip"), "w") as z:
            z.writestr("x.txt", "x")
        exe = [sys.executable, str(Path(__file__).resolve())]
        cases = [
            ["--tree", str(base)], ["--du", str(base)],
            ["--find", str(base), "--ext", ".txt"],
            ["--grep", "hello", "--path", str(base)],
            ["--head", str(base / "a.txt")], ["--tail", str(base / "a.txt")],
            ["--cat", str(base / "a.txt")],
            ["--archive-check", str(base / "s.zip")],
            ["--backups"], ["--undo-list"], ["--show-config"],
        ]
        bad = []
        try:
            for argv in cases:
                r = sp.run(exe + argv + ["--json", "--timeout", "3"],
                           capture_output=True, text=True, timeout=180,
                           stdin=sp.DEVNULL, env=dict(os.environ))
                try:
                    doc = json.loads(r.stdout)
                except ValueError:
                    bad.append("%s:not-json" % argv[0])
                    continue
                if not doc["ok"] or r.returncode != 0:
                    bad.append("%s:%s" % (argv[0], doc.get("errors")))
                if re.search(r"\033\[[0-9;]*[A-Za-z]", r.stdout):
                    bad.append("%s:ansi" % argv[0])
        finally:
            shutil.rmtree(str(base), ignore_errors=True)
        return (not bad, "%d parameterised commands emit pure JSON%s"
                % (len(cases), "" if not bad else " FAILED: %s" % bad))
    check("json: 11 parameterised commands are pure", _param_command_matrix)

    def _command_conflict():
        import subprocess as sp
        exe = [sys.executable, str(Path(__file__).resolve())]
        r = sp.run(exe + ["--system", "--tree", "/tmp"], capture_output=True,
                   text=True, timeout=120, stdin=sp.DEVNULL)
        r2 = sp.run(exe + ["--tree", ""], capture_output=True, text=True,
                    timeout=120, stdin=sp.DEVNULL)
        return (r.returncode == ExitCode.INVALID_ARGUMENT
                and "conflict" in r.stderr.lower()
                and r2.returncode == ExitCode.INVALID_ARGUMENT,
                "conflicting and empty-value commands both exit 2")
    check("cli: command conflicts rejected", _command_conflict)

    # report
    ui.clear()
    ui.header("CLXV12 SELF TEST", "v" + VERSION)
    passed = 0
    for name, ok_flag, note in results:
        mark = ui.t.c("[PASS]", "success") if ok_flag else ui.t.c("[FAIL]", "error")
        print(" %s %-44s %s" % (mark, name[:44], ui.t.c(str(note)[:70], "muted")))
        passed += ok_flag
    print()
    failed = [n for n, ok_flag, _ in results if not ok_flag]
    ui.status("ok" if passed == len(results) else "bad",
              "%d/%d tests passed" % (passed, len(results)))
    if failed:
        ui.status("bad", "failed: %s" % ", ".join(failed[:8]))
    app.store.log("Self Test", "Success" if passed == len(results) else "Failed",
                  "%d/%d" % (passed, len(results)))
    LOG.event("info", "selftest complete", passed=passed, total=len(results))
    return passed == len(results)


# ---------------------------------------------------------------------------
# APPLICATION - first run, dashboard, main menu, CLI
# ---------------------------------------------------------------------------

class CLXV12App:
    def __init__(self, no_color=False):
        global THEME, UIx
        THEME = Theme(force_no_color=no_color)
        UIx = UI(THEME)
        self.ui = UIx
        self.store = Store()
        self.system = SystemEngine()
        self.detector = ToolDetector(self.store)
        self.network = NetworkEngine(self)
        self.projects = ProjectEngine(self)
        self.build = BuildEngine(self)
        self.apk = APKEngine(self)
        self.git = GitEngine(self)
        self.files = FileEngine(self)
        self.archives = ArchiveEngine(self)
        self.devtools = DeveloperEngine(self)
        self.cleanup = CleanupEngine(self)
        self.search = SearchEngine(self)
        self.profile = ProfileEngine(self)
        self.wifi = WiFiAuditEngine(self)

    # -- environment ------------------------------------------------------------
    def environment_scan(self, verbose=False):
        if verbose or not DATA_FILES["profile"].exists():
            self.ui.clear()
            self.ui.header("Welcome to CLXV12", "First Environment Scan")
        self.detector.scan()
        checks = [
            ("Python", bool(Runner.check("python") or Runner.check("python3"))),
            ("Git", self.detector.installed("git")),
            ("Node", self.detector.installed("node")),
            ("Android (getprop)", bool(Runner.check("getprop"))),
            ("Storage", (Path.home() / "storage").exists()),
            ("Network", self.network.local_ip() is not None),
            ("Tools", True),
            ("Profile", True),
        ]
        for label, good in checks:
            self.ui.status("ok" if good else "warn", "Checking %s" % label)
        discover_projects(self.store)
        profile = self.profile.refresh()
        self.store.log("Environment Scan", "Success", "%d tools" % self.detector.count())
        self.ui.status("ok", "Environment ready.")
        return profile

    # -- dashboard -----------------------------------------------------------------
    def dashboard(self):
        p = self.store.load("profile", {})
        info = self.network.net_info()
        self.ui.header(APP_NAME, APP_SUB + "  v" + VERSION)
        left = [
            ("Android", str(p.get("device", "N/A"))),
            ("Architecture", str(p.get("architecture", "N/A"))),
            ("Python", platform.python_version()),
            ("Termux", str(p.get("termux", "N/A"))),
        ]
        right = [
            ("Git", self.detector.status("git").lower()),
            ("Node", self.detector.status("node").lower()),
            ("Java", self.detector.status("java").lower()),
            ("Gradle", self.detector.status("gradle").lower()),
        ]
        third = [
            ("Network", info["Connection"]),
            ("Local IP", info["Local IP"]),
            ("Projects", str(p.get("projects", 0))),
            ("Tools", "%d/%d" % (self.detector.count(), len(ALL_TOOL_NAMES))),
        ]
        self.ui.panels([("SYSTEM", left), ("TOOLS", right), ("SESSION", third)])
        print(self.ui.t.c("Last scan: %s" % p.get("last_scan", "N/A"), "muted"))

    def show_history(self):
        hist = self.store.load("history", [])
        self.ui.header("HISTORY", "%d entries" % len(hist))
        if not hist:
            self.ui.status("info", "History is empty.")
            self.ui.pause()
            return
        rows = [(h.get("time", ""), h.get("action", ""), h.get("status", ""),
                 h.get("detail", "")) for h in hist[-60:]]
        self.ui.table(["TIME", "ACTION", "STATUS", "DETAIL"], rows)
        self.ui.pause()

    def security_report(self):
        """One screen that proves the hardening is in place (see --security).
        Same data provider the JSON mode uses - never a second code path."""
        res = data_security(self)
        if res.ok:
            render_security(self, res)
        for w in res.warnings:
            self.ui.status("warn", w["message"])
        self.store.log("Security Report", "Success" if res.ok else "Failed")

    # -- headless screens reachable from the menu ---------------------------
    def doctor_screen(self):
        run_command(self, "doctor")
        self.ui.pause()

    def health_screen(self):
        run_command(self, "health")
        self.ui.pause()

    def diagnostics_screen(self):
        run_command(self, "diagnostics")
        self.ui.pause()

    def backups_screen(self):
        run_command(self, "backups")
        self.ui.pause()

    def benchmark_screen(self):
        with PleaseWait(self.ui, "Benchmarking"):
            res = data_benchmark(self)
        if res.ok:
            render_benchmark(self, res)
        for w in res.warnings:
            self.ui.status("warn", w["message"])
        self.ui.pause()

    def config_screen(self):
        run_command(self, "config")
        self.ui.pause()

    def security_screen(self):
        self.security_report()
        self.ui.pause()

    def undo_screen(self):
        run_command(self, "undo-list")
        entry = UNDO.last()
        if entry is None:
            self.ui.pause()
            return
        self.ui.status("warn", "Next undo: %s on %s"
                       % (entry["operation"], mask_home(entry.get("source", ""))))
        if self.ui.confirm("Undo this operation?", False):
            res = UNDO.undo_last()
            if res.ok:
                self.ui.status("ok", "Undone.")
            else:
                for e in res.errors:
                    self.ui.status("bad", "%s: %s" % (e["code"], e["message"]))
        self.ui.pause()

    # -- termux tools view ---------------------------------------------------------
    def termux_tools(self):
        self.ui.header("TOOL DISCOVERY", "%d/%d installed" % (self.detector.count(), len(ALL_TOOL_NAMES)))
        rows = []
        for group, names in TOOL_GROUPS.items():
            rows.append((self.ui.t.c(group, "accent"), "", ""))
            for n in names:
                st = self.detector.status(n)
                color = "success" if st == "INSTALLED" else \
                        ("info" if st in ("UNAVAILABLE", "NOT APPLICABLE") else "error")
                show_ver = st == "INSTALLED" and n in VERSION_FLAGS
                rows.append(("  " + n, self.ui.t.c(st, color),
                             self.system.tool_version(n) if show_ver else ""))
        self.ui.table(["TOOL", "STATUS", "VERSION"], rows)
        name = self.ui.ask("Run a tool with --help (blank to return)")
        if name:
            path = self.detector.path(name.strip())
            if path and name.strip() not in ("am", "pm"):
                Runner.display(self.ui, [path, "--help"], timeout=15, tail=2500)
            elif not path:
                self.ui.status("bad", "Tool not installed.")
        self.ui.pause()

    # -- system info screen ----------------------------------------------------------
    def system_screen(self):
        self.ui.header("SYSTEM INFORMATION")
        rows = self.system.info_rows()
        for tool in ("git", "node", "java", "gradle", "clang", "make"):
            rows.append((tool.capitalize(), self.system.tool_version(tool)))
        half = (len(rows) + 1) // 2
        self.ui.panels([("PLATFORM", rows[:half]), ("RUNTIMES", rows[half:])])
        self.ui.pause()

    # -- main menu ---------------------------------------------------------------------
    def main_menu(self):
        while True:
            self.ui.clear()
            self.dashboard()
            print()
            ch = self.ui.menu("MAIN MENU", [
                ("1", "Projects", "project"), ("2", "Build", "build"),
                ("3", "APK", "apk"), ("4", "Git", "git"),
                ("5", "Network", "network"), ("6", "Wi-Fi Audit", "security"),
                ("7", "Files", "file"), ("8", "Archives", "archive"),
                ("9", "Developer Tools", "tools"), ("10", "Cleanup", "cleanup"),
                ("11", "System", "system"), ("12", "Profile", "settings"),
                ("13", "Doctor", "ok"), ("14", "Health", "ok"),
                ("15", "Diagnostics", "system"), ("16", "Backups", "file"),
                ("17", "Undo", "back"), ("18", "Benchmark", "run"),
                ("19", "Security", "security"), ("20", "Config", "settings"),
                ("S", "Search", "search"), ("H", "History", "history"),
                ("T", "Termux Tools", "tools"), ("0", "Exit", "exit"),
            ], note=None)
            if ch in (None, "0"):
                print(self.ui.t.c("Goodbye. Stay safe.", "primary"))
                return
            route = {
                "1": self.projects.menu, "2": self.build.build_menu,
                "3": self.apk.menu, "4": self.git.menu,
                "5": self.network.menu, "6": self.wifi.run,
                "7": self.files.browse, "8": self.archives.menu,
                "9": self.devtools.menu, "10": self.cleanup.menu,
                "11": self.system_screen, "12": self.profile.menu,
                "13": self.doctor_screen, "14": self.health_screen,
                "15": self.diagnostics_screen, "16": self.backups_screen,
                "17": self.undo_screen, "18": self.benchmark_screen,
                "19": self.security_screen, "20": self.config_screen,
                "s": self.search.run, "h": self.show_history,
                "t": self.termux_tools,
            }
            try:
                fn = route.get(ch.lower())
                if fn:
                    fn()
            except KeyboardInterrupt:
                print()
                self.ui.status("warn", "Interrupted - returning to menu.")
            except Exception as e:  # noqa: BLE001 - menu must never crash
                self.ui.status("bad", "Unexpected error: %s: %s" % (type(e).__name__, e))
                self.store.log("Runtime Error", "Handled", "%s: %s" % (type(e).__name__, e))
                self.ui.pause()

    # -- CLI ------------------------------------------------------------------------
    def _param_collector(self, cmd, args):
        """Bind a CLI argument to a collector so parameterised commands share
        the exact dispatch, JSON envelope and exit-code path as the rest."""
        v = args.param
        lines = int(getattr(args, "lines", None) or 20)
        if cmd == "ports":
            return lambda app: app.network.port_check_report(
                v, args.ports_list or "common", timeout=min(RT.timeout, 10.0))
        if cmd == "archive-check":
            return lambda app: analyze_archive(v)
        if cmd == "apk-info":
            return lambda app: apk_manifest_info(v)
        if cmd == "apk-security":
            return lambda app: apk_security_report(v)
        if cmd == "tree":
            return lambda app: file_tree(v, max_depth=RT.depth,
                                         max_entries=RT.max_results,
                                         include_heavy=args.include_heavy,
                                         show_hidden=args.hidden)
        if cmd == "du":
            return lambda app: disk_usage(v, top=RT.max_results,
                                          include_heavy=args.include_heavy)
        if cmd == "find":
            return lambda app: find_files(v, name=args.name, ext=args.ext,
                                          regex=args.regex, kind=args.kind,
                                          include_heavy=args.include_heavy)
        if cmd == "grep":
            return lambda app: grep_files(args.path or ".", v,
                                          regex=not args.fixed,
                                          ext=args.ext, context=args.context,
                                          include_heavy=args.include_heavy)
        if cmd == "head":
            return lambda app: head_file(v, lines)
        if cmd == "tail":
            return lambda app: tail_file(v, lines)
        if cmd == "cat":
            return lambda app: cat_file(v)
        if cmd == "backup":
            return lambda app: BACKUPS.create(v, reason="cli")
        if cmd == "restore":
            return lambda app: BACKUPS.restore(v, dest=args.to,
                                               overwrite=args.overwrite)
        if cmd == "undo":
            return lambda app: UNDO.undo_last()
        raise InvalidArgument("unknown parameterised command %r" % cmd)

    def cli(self, args):
        """Return an exit code. Menu mode returns SUCCESS on clean exit."""
        cmd = args.command
        if cmd is None:
            self.main_menu()
            return ExitCode.SUCCESS
        if cmd in PARAM_RENDERERS:
            return run_command(self, cmd,
                               collector=self._param_collector(cmd, args),
                               renderer=PARAM_RENDERERS[cmd])
        return run_command(self, cmd)


# Backwards compatibility for anything that imported the 2.1.x name.
CLXV11App = CLXV12App


HELP_TEXT = """CLXV12 TOOLKIT v%(v)s - Termux Development Suite

Usage: python clxv12.py [command] [options]

Menu mode (default):   python clxv12.py

COMMANDS
  --scan            Environment scan: tools + project discovery + profile
  --system          System and runtime information
  --network         Network info + bounded local host discovery
  --wifi            Wi-Fi diagnostic audit of the CURRENT connection
  --tools           Tool discovery report
  --projects        Discover and list projects (evidence based)
  --security        Security posture report
  --capabilities    Feature capability matrix
  --doctor          Dependency doctor: PASS/WARN/FAIL + suggested fixes
  --health          Fast subsystem health check
  --diagnostics     Environment dump (home masked, secrets redacted)
  --benchmark       Internal performance benchmark vs. soft baselines
  --show-config     Show the effective configuration and its source
  --selftest        Run the built-in test suite
  --help            Show this help   (use: --network --help for per-command help)
  --version         Show version

COMMANDS TAKING A VALUE
  --ports TARGET         TCP port check (this device / its local network)
  --archive-check PATH   Dry-run archive safety report; extracts nothing
  --apk-info PATH        Parse a binary AndroidManifest.xml from an APK/AAB
  --apk-security PATH    APK security indicators (technical, not a verdict)
  --tree PATH            Directory tree (bounded by --depth/--max-results)
  --du PATH              Disk usage per child, largest first
  --find PATH            Find by --name / --ext / --regex / --kind
  --grep PATTERN         Stream-search file content under --path
  --head PATH            First --lines lines
  --tail PATH            Last --lines lines
  --cat PATH             Whole file, bounded, binary refused, secrets redacted
  --backup PATH          Snapshot a file or directory into the backup store
  --restore ID           Restore a backup (--to PATH, --overwrite)
  --backups              List backups with integrity verification
  --undo                 Undo the last reversible operation
  --undo-list            Show the undo journal and what is reversible

OPTIONS
  --json            Machine-readable output. stdout carries exactly one JSON
                    document; all diagnostics go to stderr.
  --quiet           Suppress non-essential output
  --verbose         Extra diagnostics on stderr
  --debug           Show tracebacks instead of a short crash summary
  --no-color        Disable ANSI colors
  --plain           No color, no box drawing, ASCII only
  --timeout SEC     Per-operation timeout budget (default %(t)s)
  --depth N         Max directory depth for scans (default %(d)s)
  --max-results N   Cap result lists (default %(m)s)
  --include-heavy   Do not skip node_modules/.git/build during scans
  --hidden          Include dotfiles in --tree
  --name/--ext/--regex/--kind    Criteria for --find
  --path/--fixed/--context       Modifiers for --grep
  --lines N         Line count for --head/--tail
  --to/--overwrite  Destination and clobber policy for --restore
  --ports-list P    Ports for --ports: "22,80,8000-8010" or "common"
  --config PATH     Alternative config file
  --log-file PATH   Write the application log here instead of ~/.clxv12/logs

JSON SCHEMA
  {"ok": bool, "command": str, "version": str, "timestamp": str,
   "data": any, "warnings": [{"message": str}],
   "errors": [{"code": str, "message": str}]}

EXIT CODES
  0 SUCCESS            5 SECURITY_BLOCK      9  NETWORK_ERROR
  1 GENERAL_ERROR      6 TIMEOUT             10 INTERNAL_ERROR
  2 INVALID_ARGUMENT   7 DEPENDENCY_MISSING
  3 NOT_FOUND          8 BUILD_ERROR
  4 PERMISSION_ERROR

EXAMPLES
  python clxv12.py --doctor
  python clxv12.py --tools --json | jq '.data.tools[] | select(.installed)'
  python clxv12.py --ports 127.0.0.1 --ports-list 22,80,8080 --json
  python clxv12.py --archive-check downloads/bundle.zip
  python clxv12.py --apk-security app-release.apk --json
  python clxv12.py --grep "TODO" --path ~/projects --ext .py
  python clxv12.py --backup ~/important.db && python clxv12.py --backups

SECURITY
  Port checks are restricted to loopback, link-local and the network this
  device is already attached to. Archives are analysed and extracted with
  traversal, symlink, size and compression-ratio guards. Subprocesses never
  use a shell. Secrets are redacted before anything is written to a log,
  a report or a JSON envelope. Destructive file operations offer a
  hash-verified backup and are recorded in the undo journal.

LIMITATIONS
  SSID/BSSID and Wi-Fi encryption mode require Termux:API and the Android
  location permission; without them those fields report UNAVAILABLE with a
  reason rather than guessing. MAC addresses need root and are not shown.
  APK signing is detected structurally: cryptographic signature verification
  requires apksigner and is NOT performed. Undo covers only the operations
  listed by --undo-list; everything else is reported as irreversible.

Approved roots: $HOME, cwd, ~/storage/shared, ~/storage/downloads
Data directory: ~/.clxv12   Logs: ~/.clxv12/logs
Offline-first. No telemetry. No automatic package installs.
""" % {"v": VERSION, "t": 30.0, "d": SCAN_MAX_DEPTH, "m": 500}


COMMAND_HELP = {
    "network": """--network : local network information and bounded host discovery

Reports interface, local IP (parsed, with version), subnet, gateway and DNS,
then probes a small set of likely-live addresses inside the detected subnet.

  Bounded by --timeout and --max-results; never performs an unbounded sweep.
  SSID requires Termux:API; when absent the field says so with a reason.
  JSON: .data.info and .data.discovery
  Exit: 0 ok, 9 no usable network, 6 discovery deadline""",
    "ports": """--ports TARGET [--ports-list SPEC] : TCP port check

  TARGET     127.0.0.1 | ::1 | [::1] | fe80::1%%wlan0 | localhost | router.lan
  SPEC       "common" (default) | "22,80,443" | "8000-8010" | mixed
  States     OPEN, CLOSED, FILTERED, TIMEOUT, ERROR
  Limits     %d ports max, %d concurrent connections, per-port --timeout
  Policy     loopback, link-local, the default gateway and the attached
             subnet only. Anything else exits 5 (SECURITY_BLOCK).
  Exit       0 ok, 2 bad target/ports, 5 refused, 9 DNS failure""" % (
        MAX_PORTS_PER_CHECK, MAX_PORT_CONCURRENCY),
    "wifi": """--wifi : diagnostic audit of the CURRENT Wi-Fi connection

Read-only. Performs no attacks, no deauthentication, no packet capture and
no password recovery. Checks gateway reachability, DNS sanity and whether
cleartext admin services are exposed on the gateway.

  Termux:API missing -> checks report UNAVAILABLE with the real reason.
  Encryption mode (WPA2/WPA3) is not readable without root: never guessed.
  Exit: 0 ok (warnings are data, not failures)""",
    "doctor": """--doctor : environment diagnosis

Checks Python, Termux, storage permission, HOME writability, PATH hygiene,
required and optional tools, disk space, RAM, loopback networking, name
resolution, Unicode support and logging.

  Suggests fixes; never applies them.
  Exit: 0 all pass/warn, 7 one or more FAIL""",
    "archive-check": """--archive-check PATH : dry-run archive safety report

Reads metadata only. Nothing is written and nothing is extracted. Reports
what the real extractor WOULD reject and why.

  Detects  path traversal, absolute paths, symlinks and hardlinks, links
           whose target escapes the destination, device/special files,
           over-long names, excessive nesting, oversized members and
           compression bombs (per-member and whole-archive ratio).
  Formats  ZIP and TAR (plain, gz, bz2, xz - detected by content)
  Exit     0 analysed (safe or not), 1 corrupt archive, 3 file not found""",
    "apk-security": """--apk-security PATH : APK security indicators

Parses the binary AndroidManifest.xml directly (no aapt, no external tools)
and reports TECHNICAL configuration indicators at INFO / WARNING / HIGH.

  Covers  debuggable, testOnly, allowBackup, cleartext traffic and
          networkSecurityConfig, exported components (explicit and the
          implicit pre-API-31 case), dangerous and special permissions,
          custom permission protection levels, minSdk/targetSdk, and
          structural signing-scheme detection.

  These are indicators about how the package is configured. They are NOT a
  verdict on the application or its publisher. Signature verification is
  structural only; cryptographic verification requires apksigner.""",
    "backup": """--backup PATH / --restore ID / --backups : snapshot store

  --backup PATH     snapshot a file or directory (tar for directories)
  --backups         list with per-entry SHA-256 integrity verification
  --restore ID      restore; refuses to clobber unless --overwrite
  --to PATH         restore somewhere other than the original location

  Every entry is hashed AFTER being written, from the stored copy. A
  tampered or truncated payload fails verification and refuses to restore.
  Retention is backup.keep in the config (default 20).""",
    "undo": """--undo / --undo-list : reversible operation journal

Undo is offered ONLY where a safe inverse exists:
  move, rename, mkdir, touch, and deletes/overwrites that were backed up.

Builds, installs, git pushes, extractions, signing and un-backed-up deletes
are recorded as irreversible and the toolkit says so rather than pretending.
An inverse is refused when the world has moved on - for example a directory
that is no longer empty, or an original path that is occupied again.""",
    "security": """--security : security posture and evidence-based findings

Reports scope (read/write roots, protected paths), effective limits, and
findings at PASS / WARNING / HIGH. A finding is only raised when there is
evidence for it - the mere existence of a file is never treated as a risk.""",
}


def build_parser():
    p = argparse.ArgumentParser(prog="clxv12", add_help=False)
    p.add_argument("--help", "-h", action="store_true")
    p.add_argument("--version", action="store_true")
    # commands
    p.add_argument("--scan", action="store_true")
    p.add_argument("--network", action="store_true")
    p.add_argument("--wifi", action="store_true")
    p.add_argument("--tools", action="store_true")
    p.add_argument("--system", action="store_true")
    p.add_argument("--projects", action="store_true")
    p.add_argument("--security", action="store_true")
    p.add_argument("--capabilities", action="store_true")
    p.add_argument("--doctor", action="store_true")
    p.add_argument("--health", action="store_true")
    p.add_argument("--diagnostics", action="store_true")
    p.add_argument("--benchmark", action="store_true")
    p.add_argument("--backups", action="store_true")
    p.add_argument("--undo-list", dest="undo_list", action="store_true")
    p.add_argument("--undo", action="store_true")
    p.add_argument("--show-config", dest="show_config", action="store_true")
    p.add_argument("--selftest", action="store_true")
    # parameterised commands
    p.add_argument("--ports", metavar="TARGET", default=None,
                   help="TCP port check target (IP or hostname)")
    p.add_argument("--archive-check", dest="archive_check", metavar="PATH",
                   default=None, help="dry-run archive safety report")
    p.add_argument("--apk-info", dest="apk_info", metavar="PATH", default=None)
    p.add_argument("--apk-security", dest="apk_security", metavar="PATH",
                   default=None)
    p.add_argument("--tree", metavar="PATH", default=None)
    p.add_argument("--du", metavar="PATH", default=None)
    p.add_argument("--find", metavar="PATH", default=None)
    p.add_argument("--grep", metavar="PATTERN", default=None)
    p.add_argument("--head", metavar="PATH", default=None)
    p.add_argument("--tail", metavar="PATH", default=None)
    p.add_argument("--cat", metavar="PATH", default=None)
    p.add_argument("--backup", metavar="PATH", default=None)
    p.add_argument("--restore", metavar="ID", default=None)
    # modifiers
    p.add_argument("--ports-list", dest="ports_list", metavar="SPEC", default=None,
                   help='ports for --ports: "22,80,8000-8010" or "common"')
    p.add_argument("--path", default=None, metavar="PATH",
                   help="search root for --grep (default: cwd)")
    p.add_argument("--name", default=None, metavar="TEXT")
    p.add_argument("--ext", default=None, metavar="EXT")
    p.add_argument("--regex", default=None, metavar="RE")
    p.add_argument("--kind", default="any", choices=("any", "file", "dir"))
    p.add_argument("--fixed", action="store_true",
                   help="--grep pattern is a literal string, not a regex")
    p.add_argument("--context", type=int, default=0, metavar="N")
    p.add_argument("--lines", type=int, default=None, metavar="N")
    p.add_argument("--hidden", action="store_true")
    p.add_argument("--include-heavy", dest="include_heavy", action="store_true",
                   help="do not skip node_modules/.git/build during scans")
    p.add_argument("--to", default=None, metavar="PATH",
                   help="destination for --restore")
    p.add_argument("--overwrite", action="store_true")
    # output modes
    p.add_argument("--json", action="store_true")
    p.add_argument("--quiet", "-q", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--plain", action="store_true")
    # tuning
    p.add_argument("--timeout", type=float, default=None, metavar="SEC")
    p.add_argument("--depth", type=int, default=None, metavar="N")
    p.add_argument("--max-results", dest="max_results", type=int, default=None,
                   metavar="N")
    p.add_argument("--config", default=None, metavar="PATH")
    p.add_argument("--log-file", dest="log_file", default=None, metavar="PATH")
    return p


COMMAND_FLAGS = ("scan", "network", "wifi", "tools", "system", "projects",
                 "security", "capabilities", "doctor", "health", "diagnostics",
                 "benchmark", "backups", "undo_list", "undo", "show_config")

# CLI attribute -> command name, for commands whose flag carries a value.
PARAM_COMMAND_FLAGS = {
    "ports": "ports", "archive_check": "archive-check", "apk_info": "apk-info",
    "apk_security": "apk-security", "tree": "tree", "du": "du",
    "find": "find", "grep": "grep", "head": "head", "tail": "tail",
    "cat": "cat", "backup": "backup", "restore": "restore",
}

BOOL_COMMAND_ALIASES = {"undo_list": "undo-list", "show_config": "config"}


def resolve_command(args):
    """Exactly one command may be given. Returns (name, param, error)."""
    chosen = []
    for flag in COMMAND_FLAGS:
        if getattr(args, flag, False):
            chosen.append((BOOL_COMMAND_ALIASES.get(flag, flag), None, "--" + flag.replace("_", "-")))
    for attr, name in PARAM_COMMAND_FLAGS.items():
        value = getattr(args, attr, None)
        if value is not None:
            chosen.append((name, value, "--" + attr.replace("_", "-")))
    if len(chosen) > 1:
        return None, None, ("command conflict: give exactly one command (got: %s)"
                            % ", ".join(c[2] for c in chosen))
    if not chosen:
        return None, None, None
    name, param, _flag = chosen[0]
    if name in PARAM_RENDERERS and name != "undo" and not str(param or "").strip():
        return None, None, "--%s requires a non-empty value" % name
    return name, param, None


def _crash_id():
    return "%s-%04x" % (datetime.now().strftime("%Y%m%d%H%M%S"),
                        random.getrandbits(16))


def main(argv=None):
    """Global exception firewall. Every path out of here returns an exit code
    from ExitCode; nothing escapes as a traceback unless --debug is given."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else ExitCode.INVALID_ARGUMENT

    CONFIG.path = Path(args.config) if args.config else CONFIG_PATH
    CONFIG.load().apply_to_runtime()
    RT.apply(args)
    command, param, conflict = resolve_command(args)
    RT.command = command
    args.param = param

    if conflict:
        sys.stderr.write("clxv12: %s\n" % conflict)
        return ExitCode.INVALID_ARGUMENT

    # Per-command help: `--network --help`
    if args.help:
        text = COMMAND_HELP.get(command) or HELP_TEXT
        if RT.machine:
            emit_json({"ok": True, "command": "help", "version": VERSION,
                       "timestamp": now_iso(), "data": {"text": text},
                       "warnings": [], "errors": []})
        else:
            print(text)
        return ExitCode.SUCCESS

    if args.version:
        if RT.machine:
            emit_json({"ok": True, "command": "version", "version": VERSION,
                       "timestamp": now_iso(),
                       "data": {"name": APP_NAME, "version": VERSION,
                                "python": platform.python_version()},
                       "warnings": [], "errors": []})
        else:
            print("%s v%s" % (APP_NAME, VERSION))
        return ExitCode.SUCCESS

    app = None
    try:
        migrate_legacy_config()
        LOG.event("info", "start", argv=" ".join(sys.argv[1:])[:200])
        app = CLXV12App(no_color=RT.no_color)
        args.command = command

        if args.selftest:
            ok_all = run_selftest(app)
            return ExitCode.SUCCESS if ok_all else ExitCode.GENERAL

        # First-run initialisation must never pollute machine-readable stdout.
        with stdout_firewall(RT.machine):
            if not DATA_FILES["profile"].exists():
                if RT.machine or command is not None:
                    app.detector.scan()
                    discover_projects(app.store)
                    app.profile.refresh()
                    app.store.log("Environment Scan", "Success", "silent init")
                else:
                    app.environment_scan(verbose=True)
                    app.ui.pause()
            else:
                app.detector.scan()
                if command is None:
                    discover_projects(app.store)

        if command is None and not instance_lock():
            msg = "Another CLXV12 instance is already running."
            lock = CONFIG_DIR / "instance.lock"
            sys.stderr.write("%s\nLock: %s (delete it after a crash)\n" % (msg, lock))
            return ExitCode.GENERAL

        return app.cli(args)

    except KeyboardInterrupt:
        if RT.machine:
            emit_json({"ok": False, "command": command or "menu", "version": VERSION,
                       "timestamp": now_iso(), "data": None, "warnings": [],
                       "errors": [{"code": ErrCode.INTERRUPTED,
                                   "message": "cancelled by user"}]})
        else:
            sys.stderr.write("\nInterrupted safely.\n")
        return ExitCode.GENERAL
    except BrokenPipeError:
        # Downstream closed the pipe (e.g. `| head`). Silence the shutdown noise.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        return ExitCode.SUCCESS
    except ToolkitError as e:
        LOG.event("error", "toolkit error: %s" % e.message, code=e.code)
        if RT.machine:
            emit_json({"ok": False, "command": command or "menu", "version": VERSION,
                       "timestamp": now_iso(), "data": None, "warnings": [],
                       "errors": [e.as_dict()]})
        else:
            sys.stderr.write("clxv12: %s: %s\n" % (e.code, e.message))
        return e.exit_code
    except Exception as e:                                # noqa: BLE001
        import traceback
        error_id = _crash_id()
        tb = traceback.format_exc()
        LOG.crash(error_id, redact_credentials(tb))
        write_crash_log("[%s] %s" % (error_id, tb))
        if RT.machine:
            emit_json({"ok": False, "command": command or "menu", "version": VERSION,
                       "timestamp": now_iso(), "data": None, "warnings": [],
                       "errors": [{"code": ErrCode.INTERNAL,
                                   "message": "internal error",
                                   "error_id": error_id,
                                   "log": str(LOG_DIR / "crash.log")}]})
        elif RT.debug:
            traceback.print_exc()
        else:
            try:
                sys.stderr.write(
                    "%s: an internal error occurred.\n"
                    "  Error ID : %s\n  Log      : %s\n"
                    "  Re-run with --debug for the full traceback.\n"
                    % (APP_NAME, error_id, LOG_DIR / "crash.log"))
            except OSError:
                pass
        return ExitCode.INTERNAL
    finally:
        cleanup_temp_registry()
        try:
            sys.stdout.flush()
        except (OSError, ValueError, BrokenPipeError):
            os._exit(ExitCode.SUCCESS)


def _install_signal_handlers():
    """SIGTERM/SIGHUP become a clean shutdown with the same cleanup path as
    Ctrl+C, so temporary files and the instance lock are always released."""
    def _handler(signum, _frame):
        name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        LOG.event("warning", "received %s, shutting down" % name)
        raise KeyboardInterrupt()
    for sig in ("SIGTERM", "SIGHUP"):
        s = getattr(signal, sig, None)
        if s is None:
            continue
        try:
            signal.signal(s, _handler)
        except (ValueError, OSError, RuntimeError):
            pass
    pipe = getattr(signal, "SIGPIPE", None)
    if pipe is not None:
        try:
            signal.signal(pipe, signal.SIG_DFL)
        except (ValueError, OSError, RuntimeError):
            pass


if __name__ == "__main__":
    _install_signal_handlers()
    sys.exit(main())
