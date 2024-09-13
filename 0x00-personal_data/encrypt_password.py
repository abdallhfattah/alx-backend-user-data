#!/usr/bin/env python3
"""module to encrypt password before storing it inside of the database"""

import bcrypt


def hash_password(password: str) -> bytes:
    """hashing my password"""
    # converting password to array of bytes
    bytes = password.encode("utf-8")

    # generating the salt
    salt = bcrypt.gensalt()

    return bcrypt.hashpw(bytes, salt)


def is_valid(hashed_password: bytes, password: str) -> bool:
    """validating password"""

    return bcrypt.checkpw(password.encode("utf-8"), hashed_password)
