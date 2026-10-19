
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError,
)
from bson import ObjectId
from datetime import datetime, timezone


password_hasher = PasswordHasher()


class User(UserMixin):
    def __init__(
        self,
        user_id,
        username,
        email,
        password_hash,
    ):
        self.id = str(user_id)
        self.username = username
        self.email = email
        self.password_hash = password_hash

    @staticmethod
    def hash_password(password):
        return password_hasher.hash(password)

    def verify_password(self, password):
        try:
            return password_hasher.verify(
                self.password_hash,
                password,
            )
        except (
            VerifyMismatchError,
            VerificationError,
            InvalidHashError,
        ):
            return False

    def to_document(self):
        return {
            "_id": ObjectId(self.id),
            "username": self.username,
            "email": self.email,
            "password_hash": self.password_hash,
            "created_at": datetime.now(timezone.utc),
        }

    @classmethod
    def from_document(cls, document):
        if not document:
            return None

        return cls(
            user_id=document["_id"],
            username=document["username"],
            email=document["email"],
            password_hash=document["password_hash"],
        )
