"""Section 5: Logging — Visual Validation"""

from __future__ import annotations

import logging
import sys


def get_visual_logger(name: str = "visual_validation", level: str = "INFO") -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        log.setLevel(getattr(logging, level.upper(), logging.INFO))
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[%(asctime)s] VISUAL %(levelname)s %(message)s"))
        log.addHandler(h)
    return log
