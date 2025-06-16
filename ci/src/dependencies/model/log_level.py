import logging
import os

LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING").upper()


def get_log_level() -> int:
    if LOG_LEVEL == "CRITICAL":
        return logging.CRITICAL
    elif LOG_LEVEL == "FATAL":
        return logging.FATAL
    elif LOG_LEVEL == "ERROR":
        return logging.ERROR
    elif LOG_LEVEL == "WARNING":
        return logging.WARNING
    elif LOG_LEVEL == "WARN":
        return logging.WARN
    elif LOG_LEVEL == "INFO":
        return logging.INFO
    elif LOG_LEVEL == "DEBUG":
        return logging.DEBUG
    return logging.WARNING
