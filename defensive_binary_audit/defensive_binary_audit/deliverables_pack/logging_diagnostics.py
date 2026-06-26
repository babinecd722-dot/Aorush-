"""Section 5: Logging & Diagnostics — Deliverables Packaging"""

from __future__ import annotations

import logging
import sys


def get_deliverables_logger(name: str = "deliverables_pack", level: str = "INFO") -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        log.setLevel(getattr(logging, level.upper(), logging.INFO))
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[%(asctime)s] DLV %(levelname)s %(message)s"))
        log.addHandler(h)
    return log
