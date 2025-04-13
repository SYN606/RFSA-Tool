import logging
from config.settings import CONFIG
import os


def setup_logger(name="RouterSecAssist"):
    """
    Sets up and returns a configured logger.
    """
    log_level = getattr(logging, CONFIG["log_level"].upper(), logging.INFO)
    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s",
                                  "%H:%M:%S")

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler
    if CONFIG["log_to_file"]:
        os.makedirs(os.path.dirname(CONFIG["log_file_path"]), exist_ok=True)
        fh = logging.FileHandler(CONFIG["log_file_path"])
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger


# Optional: basic log shortcut functions
def log_info(msg):
    logger = logging.getLogger("RouterSecAssist")
    logger.info(msg)


def log_warn(msg):
    logger = logging.getLogger("RouterSecAssist")
    logger.warning(msg)


def log_error(msg):
    logger = logging.getLogger("RouterSecAssist")
    logger.error(msg)
