import logging
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG_LEVEL = os.environ.get("AIMY_LOG_LEVEL", "WARNING").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.WARNING),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
