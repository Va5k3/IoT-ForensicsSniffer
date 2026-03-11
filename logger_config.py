import logging
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_configured: set = set()


def setup_logger(name: str) -> logging.Logger:
    """Vrati logger sa file + console handlerom."""
    log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
    log_file      = os.getenv("LOG_FILE", "forensics.log")
    log_level     = getattr(logging, log_level_str, logging.INFO)

    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    if name not in _configured:
        _configured.add(name)

        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Konzola
        ch = logging.StreamHandler()
        ch.setLevel(log_level)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        # Fajl
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setLevel(log_level)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except OSError as e:
            logger.warning(f"Ne mogu otvoriti log fajl '{log_file}': {e}")

        logger.propagate = False

    return logger
