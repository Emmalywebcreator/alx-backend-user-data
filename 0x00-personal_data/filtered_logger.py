#!/usr/bin/env python3
"""
A function that returns the log message obfuscated
"""

import re


def filter_datum(fields, redaction, message, separator):
    """
    Return obfuscated messafe
    """
    return re.sub(
            r'(' + '|'.join([f'{field}=[^;]+' for field in fields]) + ')',
            lambda m: m.group(0).split('=')[0] + '=' + redaction, message
    )

