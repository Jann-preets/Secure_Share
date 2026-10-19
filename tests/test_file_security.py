
from datetime import datetime, timezone
from unittest.mock import patch

import mongomock
import pytest
from bson import ObjectId

from app import create_app


@pytest.fixture
def security_test_setup():
    """Create an isolated Flask app and in-memory test database."""
    app = create_app()
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY="test-secret-key",
        MASTER_KEY="",
    )

    # Prevent this test app from using the real Atlas database.
    db = mongomock.MongoClient().secureshare_test
    app.extensions["mongo_client"] = None
    app.extensions["mongo_db"] = db
    app.extensions["mongo_status"] = "Test database"

    owner_id = ObjectId()
    recipient_id = ObjectId()
    other_user_id = ObjectId()
    file_id = ObjectId()

    db.users.insert_many([
        {
            "_id": owner_id,
            "username": "owner",
            "email": "owner@example.com",
            "password_hash": "test",
        },
        {
            "_id": recipient_id,
            "username": "recipient",
            "email": "recipient@example.com",
            "password_hash": "test",
        },
        {
            "_id": other_user_id,
            "username": "other",
            "email": "other@example.com",
            "password_hash": "test",
        },
    ])

    db.file_metadata.insert_one({
        "_id": file_id,
        "owner_id": owner_id,
        "storage_id": ObjectId(),
        "original_filename": "private.txt",
        "content_type": "text/plain",
        "size": 12,
        "sha256": "unused-in-these-tests",
        "nonce": "unused-in-these-tests",
        "created_at": datetime.now(timezone.utc),
    })

    return app, db, owner_id, recipient_id, other_user_id, file_id


def login_as(client, user_id):
    """Log in a test user through Flask's session."""
    with client.session_transaction() as session:
        session["_user_id"] = str(user_id)
        session["_fresh"] = True


def test_other_user_cannot_download_private_file(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    client = app.test_client()
    login_as(client, other_user_id)

    response = client.get(f"/files/download/{file_id}")

    assert response.status_code == 404


def test_recipient_cannot_download_after_share_revoked(
    security_test_setup,
):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    # Create a share, then revoke it.
    db.shares.insert_one({
        "file_id": file_id,
        "owner_id": owner_id,
        "recipient_id": recipient_id,
        "active": False,
        "created_at": datetime.now(timezone.utc),
        "revoked_at": datetime.now(timezone.utc),
    })

    client = app.test_client()
    login_as(client, recipient_id)

    # The download must be denied before GridFS or decryption is reached.
    with patch("routes.files.get_file_storage") as mock_storage:
        response = client.get(f"/files/download/{file_id}")

    assert response.status_code == 404
    mock_storage.assert_not_called()


def test_download_rejects_file_when_sha256_does_not_match(
    security_test_setup,
):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    # Log in as the file owner.
    client = app.test_client()
    login_as(client, owner_id)

    # Give the metadata an intentionally incorrect SHA-256 hash.
    db.file_metadata.update_one(
        {"_id": file_id},
        {"$set": {"sha256": "incorrect-hash"}},
    )

    # Mock encrypted storage and decryption so the test focuses
    # specifically on the SHA-256 integrity check.
    with (
        patch("routes.files.get_file_storage") as mock_storage,
        patch(
            "routes.files.load_master_key",
            return_value=b"x" * 32,
        ),
        patch(
            "routes.files.decrypt_file",
            return_value=b"original file content",
        ),
    ):
        mock_storage.return_value.get.return_value.read.return_value = (
            b"mock ciphertext"
        )

        response = client.get(f"/files/download/{file_id}")

    assert response.status_code == 409


from io import BytesIO


def test_upload_rejects_missing_file(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    client = app.test_client()
    login_as(client, owner_id)

    response = client.post(
        "/files/upload",
        data={},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/files/upload")
    assert db.file_metadata.count_documents({}) == 1


def test_upload_rejects_invalid_filename(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    client = app.test_client()
    login_as(client, owner_id)

    response = client.post(
        "/files/upload",
        data={"file": (BytesIO(b"test content"), "...")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/files/upload")
    assert db.file_metadata.count_documents({}) == 1


def test_upload_rejects_file_over_size_limit(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    client = app.test_client()
    login_as(client, owner_id)

    app.config["MAX_CONTENT_LENGTH"] = 10

    response = client.post(
        "/files/upload",
        data={"file": (BytesIO(b"A" * 11), "large.txt")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 413
    assert db.file_metadata.count_documents({}) == 1


def test_logged_out_user_is_redirected_from_dashboard(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    client = app.test_client()
    response = client.get("/dashboard", follow_redirects=False)

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_rejects_incorrect_password(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    from security.user import User

    # Store a valid Argon2 password hash for the owner.
    db.users.update_one(
        {"_id": owner_id},
        {"$set": {"password_hash": User.hash_password("CorrectPassword123!")}},
    )

    client = app.test_client()
    response = client.post(
        "/login",
        data={
            "email": "owner@example.com",
            "password": "WrongPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert b"Invalid email or password." in response.data
    
    with client.session_transaction() as session:
        assert "_user_id" not in session



def test_registration_rejects_short_password(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    client = app.test_client()
    response = client.post(
        "/register",
        data={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "short",
            "confirm_password": "short",
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert b"Password must contain at least 12 characters." in response.data
    assert db.users.count_documents({"email": "newuser@example.com"}) == 0



def test_successful_login_redirects_to_dashboard(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    from security.user import User

    db.users.update_one(
        {"_id": owner_id},
        {"$set": {
            "password_hash": User.hash_password("CorrectPassword123!")
        }},
    )

    client = app.test_client()
    response = client.post(
        "/login",
        data={
            "email": "owner@example.com",
            "password": "CorrectPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]

    with client.session_transaction() as session:
        assert "_user_id" in session


def test_logout_ends_session_and_protects_dashboard(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    client = app.test_client()
    login_as(client, owner_id)

    response = client.post("/logout", follow_redirects=False)
    assert response.status_code == 302

    with client.session_transaction() as session:
        assert "_user_id" not in session

    dashboard_response = client.get("/dashboard", follow_redirects=False)
    assert dashboard_response.status_code == 302
    assert "/login" in dashboard_response.headers["Location"]



def test_registration_rejects_duplicate_email(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    client = app.test_client()
    response = client.post(
        "/register",
        data={
            "username": "newusername",
            "email": "owner@example.com",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert b"already registered" in response.data
    assert db.users.count_documents(
        {"email": "owner@example.com"}
    ) == 1



def test_registration_rejects_duplicate_username(security_test_setup):
    app, db, owner_id, recipient_id, other_user_id, file_id = (
        security_test_setup
    )

    client = app.test_client()
    response = client.post(
        "/register",
        data={
            "username": "owner",
            "email": "different@example.com",
            "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert b"already registered" in response.data
    assert db.users.count_documents({"username": "owner"}) == 1
    assert db.users.count_documents(
        {"email": "different@example.com"}
    ) == 0
