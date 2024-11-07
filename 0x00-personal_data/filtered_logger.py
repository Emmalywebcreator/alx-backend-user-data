#!/usr/bin/env python3
"""
A function that returns the log message obfuscated
"""

import re
import logging
from typing import List


def filter_datum(fields: List[str], redaction: str, message: str, separator: str):
    """
    Return obfuscated messafe
    """
    return re.sub(
            r'(' + '|'.join([f'{field}=[^;]+' for field in fields]) + ')',
            lambda m: m.group(0).split('=')[0] + '=' + redaction, message
    )

class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class that filters PII fields in log record
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPERATOR = ";"


    def __init__(self, fields: List[str]):
        """Initializws the RedactingFromatter with specific fields to redact"""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields


    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record be redaction specified fields"""
        message = super().format(record)
        return filter_datum(self.fields, self.REDACTION, message, self.SEPERATOR)


import logging
from typing import List


PII_FIELDS = ("name", "email", "phone", "ssn", "password")

def get_logger() -> logging.Logger:
    """Creates a logger to handle user data with sensitive information redacted."""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    Set up StreamHandler with RedactingFormatter
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(fields=PII_FIELDS))
    logger.addHandler(stream_handler)

    return logger
