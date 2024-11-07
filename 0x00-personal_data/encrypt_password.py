#!/usr/bin/env python3
"""
Encrypt password using bycrypt
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password with a salt using bcrypt and returns the salted, hashed password.
    """
    """Generate a salt"""
    salt = bcrypt.gensalt()
    """Hash the password with the generated salt"""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

