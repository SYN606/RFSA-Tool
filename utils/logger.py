import logging
from config.settings import CONFIG
import os

def setup_logger(name="RouterSecAssist"):
    """
    Sets up and returns a configured logger.
    Prevents duplicate handlers.
    """
    log_level = getattr(logging, CONFIG["log_level"].upper(), logging.INFO)
    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    if not logger.handlers:
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")

        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        # File handler with rotation
        if CONFIG["log_to_file"]:
            os.makedirs(os.path.dirname(CONFIG["log_file_path"]), exist_ok=True)
            try:
                from logging.handlers import RotatingFileHandler
                fh = RotatingFileHandler(CONFIG["log_file_path"], maxBytes=1024*1024, backupCount=3)
            except ImportError:
                fh = logging.FileHandler(CONFIG["log_file_path"])
            fh.setFormatter(formatter)
            logger.addHandler(fh)

    return logger

# Ensure logger is set up at import
setup_logger()

def log_info(msg):
    logger = logging.getLogger("RouterSecAssist")
    logger.info(msg)

def log_warn(msg):
    logger = logging.getLogger("RouterSecAssist")
    logger.warning(msg)

def log_error(msg):
    logger = logging.getLogger("RouterSecAssist")
    logger.error(msg)
