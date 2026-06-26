"""Section 5: Logging & Diagnostics — Behavioral Validation"""

from __future__ import annotations

import logging
import sys


def get_behavioral_logger(name: str = "behavioral_validation", level: str = "INFO") -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        log.setLevel(getattr(logging, level.upper(), logging.INFO))
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[%(asctime)s] BEHAV %(levelname)s %(message)s"))
        log.addHandler(h)
    return log
