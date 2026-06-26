"""Section 5: Logging — CI Validation"""

from __future__ import annotations

import logging
import sys


def get_ci_logger(name: str = "ci_validation", level: str = "INFO") -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        log.setLevel(getattr(logging, level.upper(), logging.INFO))
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[%(asctime)s] CI %(levelname)s %(message)s"))
        log.addHandler(h)
    return log
