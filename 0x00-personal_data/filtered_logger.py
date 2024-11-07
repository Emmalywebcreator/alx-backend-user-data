#!/usr/bin/env python3
"""
A function that returns the log message obfuscated
"""

import logging
import mysql.connector
from mysql.connector import connection
import os
import re
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


PII_FIELDS = ("name", "email", "phone", "ssn", "password")

def get_logger() -> logging.Logger:
    """Creates a logger to handle user data with sensitive information redacted."""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False


    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(fields=PII_FIELDS))
    logger.addHandler(stream_handler)

    return logger


def get_db() ->  connection.MySQLConnection:
    """
    Connect to the secure Holberton database using environment variables for
    for credentials.
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA__DB_HOST", "localhost")
    database = os.getenv("PERSONAL_DATA_DB_NAME")

    return mysql.connector.connect(
            user=username,
            password=password,
            host=host,
            database=database
        )


def main():
    """Main function to retrieve and filter user data from the database"""
    logger = get_logger()

    """Retrieve database connection"""
    db = get_db()
    cursor = db.cursor(dictionary=True)

    """Fetch all rows from the users table"""
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    """Log each row with filtered data"""
    for user in users:
        """Create a log-friendly message with sensitive data redacted"""
        message = f"name={user['name']}; email={user['email']}; phone={user['phone']}; " \
                  f"ssn={user['ssn']}; password={user['password']}; ip={user['ip']}; " \
                  f"last_login={user['last_login']}; user_agent={user['user_agent']}"
        logger.info(message)

    """Close database connection"""
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
