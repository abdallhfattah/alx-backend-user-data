#!/usr/bin/env python3
"""module to filter logs"""

import re
from typing import List
import mysql.connector
import logging
import os


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def get_db() -> mysql.connector.connection.MYSQLConnection:
    """Connection to MySQL environment"""
    db_connect = mysql.connector.connect(
        user=os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        password=os.getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        host=os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        database=os.getenv("PERSONAL_DATA_DB_NAME"),
    )
    return db_connect


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


def main():
    """
    Obtain a database connection using get_db and retrieves all rows
    in the users table and display each row under a filtered format
    """
    # connecting to the database
    db = get_db()
    # cursor allow's you to make quires
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    # (column_name, type_code, display_size, internal_size, ...)
    # we need column_name
    fields = [i[0] for i in cursor.description]

    # Get the logger instance
    logger = get_logger()

    # Iterate over each row from the result set
    for row in cursor:
        # Create a dictionary that maps field names to their respective values
        row_data = dict(zip(fields, row))
        # Create a log message in the form of key=value pairs separated by ";"
        message = "; ".join([f"{key}={value}"
                            for key, value in row_data.items()])
        # Log the filtered message
        logger.info(message)

    # Close the cursor and database connection
    cursor.close()
    db.close()


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


if __name__ == "__main__":
    main()
