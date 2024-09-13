#!/usr/bin/env python3
"""module to filter logs"""

import re
from typing import List

import logging


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def get_logger() -> logging.Logger:
    """Returns a Logger Object"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.addHandler(stream_handler)

    return logger


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """init"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self._fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """formating the record"""
        original_message = super().format(record)
        redacted_message = filter_datum(
            self._fields,
            RedactingFormatter.REDACTION,
            original_message,
            RedactingFormatter.SEPARATOR,
        )
        return redacted_message


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """
    Replace sensitive fields in a log message with a redaction string.

    Args:
        fields (List[str]): List of field names to redact.
        redaction (str): The string to replace the field values with.
        message (str): The log message to filter.
        separator (str): The char that separates key-val pairs in the message.

    Returns:
        str: The log message with redacted fields.
    """
    for field in fields:
        pattern = rf"({field})=[^{separator}]*"
        message = re.sub(pattern, rf"\1={redaction}", message)
    return message
