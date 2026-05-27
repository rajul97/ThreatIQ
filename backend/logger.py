import os
import sys
import json
import time
import logging
import logging.handlers
from pathlib import Path
from datetime import datetime, timezone


# ── Constants ──────────────────────────────────────────────────
LOG_DIR      = os.path.join(os.path.dirname(__file__), 'logs')
LOG_FILE     = os.path.join(LOG_DIR, 'threatiq.log')
ERROR_FILE   = os.path.join(LOG_DIR, 'error.log')
MAX_BYTES    = 10 * 1024 * 1024   # 10 MB
BACKUP_COUNT = 5
LOG_LEVEL    = os.getenv('LOG_LEVEL', 'INFO').upper()


# ══════════════════════════════════════════════════════════════
# FORMATTERS
# ══════════════════════════════════════════════════════════════

class ThreatIQFormatter(logging.Formatter):
    """Custom formatter with optional ANSI color for console output."""

    COLORS = {
        'DEBUG'    : '\033[36m',   # Cyan
        'INFO'     : '\033[32m',   # Green
        'WARNING'  : '\033[33m',   # Yellow
        'ERROR'    : '\033[31m',   # Red
        'CRITICAL' : '\033[35m',   # Magenta
    }
    RESET = '\033[0m'
    BOLD  = '\033[1m'

    def __init__(self, use_color: bool = True):
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        now   = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        level = record.levelname.ljust(8)

        if self.use_color:
            color     = self.COLORS.get(record.levelname, '')
            level_str = f"{color}{self.BOLD}{level}{self.RESET}"
        else:
            level_str = level

        base = f"[{now}] {level_str} | {record.name} | {record.getMessage()}"

        # FIX Bug 1: (None, None, None) is a truthy 3-tuple — logging sets exc_info
        # to that when exc_info=True is passed but no active exception exists.
        # Must check exc_info[0] is not None to avoid appending a blank line.
        if record.exc_info and record.exc_info[0] is not None:
            base += f"\n{self.formatException(record.exc_info)}"

        return base


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured log ingestion (SIEM / ELK)."""

    def format(self, record: logging.LogRecord) -> str:
        # FIX: json imported at module level — not inside method on every call
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level':     record.levelname,
            'logger':    record.name,
            'message':   record.getMessage(),
            'module':    record.module,
            'funcName':  record.funcName,
            'lineNo':    record.lineno,
        }
        # FIX Bug 1 (same): guard against (None, None, None) truthy tuple
        if record.exc_info and record.exc_info[0] is not None:
            log_entry['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


# ══════════════════════════════════════════════════════════════
# SETUP
# ══════════════════════════════════════════════════════════════

def setup_logger(name: str = 'threatiq') -> logging.Logger:
    """
    Configure and return the ThreatIQ logger.
    - Console  : colored human-readable output
    - File     : rotating plain text (all levels)
    - Error    : rotating JSON  (ERROR+ only, for SIEM ingestion)
    """
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger   # already configured — avoid duplicate handlers

    level = getattr(logging, LOG_LEVEL, logging.INFO)
    logger.setLevel(level)
    logger.propagate = False

    # ── Console ────────────────────────────────────────────────
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(ThreatIQFormatter(use_color=True))
    logger.addHandler(console)

    # ── Rotating plain text file ───────────────────────────────
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(ThreatIQFormatter(use_color=False))
    logger.addHandler(file_handler)

    # ── Rotating JSON error file (SIEM) ────────────────────────
    error_handler = logging.handlers.RotatingFileHandler(
        ERROR_FILE,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(JSONFormatter())
    logger.addHandler(error_handler)

    logger.info(f"ThreatIQ logger initialized | level={LOG_LEVEL} | dir={LOG_DIR}")
    return logger


# ══════════════════════════════════════════════════════════════
# FLASK REQUEST MIDDLEWARE
# ══════════════════════════════════════════════════════════════

def log_request_start():
    """
    Flask before_request hook — records request start time.
    Register in app.py:  app.before_request(log_request_start)
    """
    # FIX: time imported at module level — not inside function
    from flask import g
    g.start_time = time.time()


def log_request(response):
    """
    Flask after_request hook — logs every API call with duration.
    Register in app.py:  app.after_request(log_request)
    """
    from flask import request, g

    _logger  = logging.getLogger('threatiq')
    duration = int((time.time() - getattr(g, 'start_time', time.time())) * 1000)
    status   = response.status_code

    log_level = (
        logging.ERROR   if status >= 500 else
        logging.WARNING if status >= 400 else
        logging.INFO
    )

    _logger.log(
        log_level,
        f"HTTP {request.method} {request.path} → {status} | "
        f"{duration}ms | ip={request.remote_addr}"
    )
    return response


# ══════════════════════════════════════════════════════════════
# ANALYSIS EVENT LOGGER
# ══════════════════════════════════════════════════════════════

class AnalysisLogger:
    """Structured logger for threat analysis lifecycle events."""

    def __init__(self):
        self._log = logging.getLogger('threatiq.analysis')

    def started(self, user_id: int, input_type: str, ioc_count: int):
        self._log.info(
            f"ANALYSIS_START | user={user_id} | type={input_type} | iocs={ioc_count}"
        )

    def completed(self, user_id: int, analysis_id: int,
                  threat_level: str, confidence: int,
                  ttp_count: int, duration_ms: int):
        self._log.info(
            f"ANALYSIS_COMPLETE | user={user_id} | id={analysis_id} | "
            f"level={threat_level} | confidence={confidence}% | "
            f"ttps={ttp_count} | time={duration_ms}ms"
        )

    def failed(self, user_id: int, error: str):
        self._log.error(
            f"ANALYSIS_FAILED | user={user_id} | error={error}"
        )

    def api_call(self, api_name: str, ioc: str,
                 success: bool, duration_ms: int):
        # FIX: str(ioc) prevents TypeError if ioc is not a string
        # FIX Bug 2: ellipsis was always appended even for IOCs ≤ 20 chars,
        # making short values look truncated when they weren't.
        ioc_str = str(ioc)
        ioc_display = (ioc_str[:20] + '…') if len(ioc_str) > 20 else ioc_str
        self._log.debug(
            f"API_CALL | api={api_name} | ioc={ioc_display} | "
            f"success={success} | time={duration_ms}ms"
        )

    def pdf_generated(self, user_id: int, analysis_id: int, pages: int):
        self._log.info(
            f"PDF_GENERATED | user={user_id} | analysis={analysis_id} | pages={pages}"
        )

    def sigma_generated(self, user_id: int, rule_count: int):
        self._log.info(
            f"SIGMA_GENERATED | user={user_id} | rules={rule_count}"
        )


# ── Singleton ──────────────────────────────────────────────────
analysis_logger = AnalysisLogger()
