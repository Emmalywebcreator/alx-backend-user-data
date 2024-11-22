#!/usr/bin/env python3
"""
Auth module for managing API authentication
"""

from typing import List, TypeVar
from flask import request


class Auth:
    """Class to manage the API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if authentication is required for a given path
        Returns:
            bool: False (authentication check logic will be added later)
        """
        if path is None:
            return True

        if not excluded_paths:
            return True

        if path[-1] != '/':
            path += '/'

        for excluded_path in excluded_paths:
            if excluded_path[-1] != '/':
                excluded_path += '/'

            if '*' in excluded_path:
                base_path = excluded_path.rstrip('*')
                if path.startswith(base_path):
                    return False
            elif excluded_path == path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the authorization header from the request
        Returns:
            str: None (to be implemented)
        """
        if request is None:
            return None
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request
        Returns:
            TypeVar('User'): None (to be implemented)
        """
        return None
