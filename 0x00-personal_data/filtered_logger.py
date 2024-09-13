#!/usr/bin/env python3
"""module to filter logs"""

import re
from typing import List

import logging


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self._fields = fields

    def format(self, record: logging.LogRecord) -> str:
        # Get the base message with the default format
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
