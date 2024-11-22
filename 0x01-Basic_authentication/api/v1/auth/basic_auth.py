#!/usr/bin/env python3
"""
Basic Auth module
"""

from typing import TypeVar
from models.user import User
import base64
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ BasicAuth class for basic authentication, inheriting from Auth. """
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization header.
        """

        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes a Base64-encoded authorization header.
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
                self, decoded_base64_authorization_header: str
            ) -> (str, str):
        """
        Extracts user email and password from the decoded Base64
        authorization header
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None

        user_email, user_password = (
                decoded_base64_authorization_header.split(":", 1)
            )
        return user_email, user_password

    def user_object_from_credentials(
                self, user_email: str, user_pwd: str
            ) -> TypeVar('User'):
        """Retrieves User instance based on email and password."""

        """Check if email and password are valid strings"""
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        """Search for user by email in database"""
        try:
            users = User.search({"email": user_email})
        except Exception:
            return None

        if not users:
            return None

        """Check if password is correct for the found user"""
        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None) -> TypeVar('User'):
        """
        This method retrieves the user credentials from the
        authorization header, decodes them, and validates the
        user by checking the credentials against the user database.
        """

        """Retrieves Authorization header"""
        authorization_header = self.authorization_header(request)
        if authorization_header is None:
            return None

        """Extracts Base64 portion from header"""
        base64_credentials = self.extract_base64_authorization_header(
                authorization_header
            )
        if base64_credentials is None:
            return None

        """Decode Base64 credentials"""
        decoded_credentials = self.decode_base64_authorization_header(
                base64_credentials
            )
        if decoded_credentials is None:
            return None

        """Extract user email and password"""
        user_email, user_password = self.extract_user_credentials(
                decoded_credentials
            )
        if user_email is None or user_password is None:
            return None

        """Fetchs and validate the User object"""
        user = self.user_object_from_credentials(
                user_email, user_password
            )
        return user
