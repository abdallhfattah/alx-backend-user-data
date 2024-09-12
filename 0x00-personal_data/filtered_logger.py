#!/usr/bin/env python3
"""module to filter logs"""

import re
from typing import List


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
