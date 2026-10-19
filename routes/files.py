
import hashlib
import hmac
from datetime import datetime, timezone
from io import BytesIO
from uuid import uuid4

from bson import ObjectId
from bson.errors import InvalidId
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from gridfs.errors import NoFile
from pymongo.errors import PyMongoError
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from services.encryption import (
    encrypt_file,
    decrypt_file,
    load_master_key,
)
from services.storage import get_file_storage


files_bp = Blueprint("files", __name__)


def log_audit_event(db, actor_id, action, file_id=None):
    """Record a security-relevant event without interrupting the main action."""
    try:
        db.audit_logs.insert_one({
            "user_id": ObjectId(actor_id),
            "action": action,
            "file_id": ObjectId(file_id) if file_id else None,
            "timestamp": datetime.now(timezone.utc),
        })
    except Exception:
        current_app.logger.exception(
            "Could not record audit event: %s", action
        )


@files_bp.route("/files/upload", methods=["GET", "POST"])
@login_required
def upload():
    db = current_app.extensions.get("mongo_db")

    if db is None:
        flash("Database is unavailable. Please try again.", "error")
        return render_template("upload.html"), 503

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a file to upload.", "error")
            return redirect(url_for("files.upload"))

        original_filename = secure_filename(uploaded_file.filename)

        if not original_filename:
            flash("Please choose a valid filename.", "error")
            return redirect(url_for("files.upload"))

        file_data = uploaded_file.read()

        if len(file_data) > current_app.config["MAX_CONTENT_LENGTH"]:
            flash("The file exceeds the 16 MB limit.", "error")
            return redirect(url_for("files.upload"))

        stored_id = None
        storage = None

        try:
            master_key = load_master_key(
                current_app.config["MASTER_KEY"]
            )
            encrypted = encrypt_file(file_data, master_key)

            storage = get_file_storage(db)
            stored_id = storage.put(
                encrypted["ciphertext"],
                filename=f"{uuid4().hex}.bin",
                content_type="application/octet-stream",
            )

            metadata_id = ObjectId()

            try:
                db.file_metadata.insert_one({
                    "_id": metadata_id,
                    "owner_id": ObjectId(current_user.id),
                    "storage_id": stored_id,
                    "original_filename": original_filename,
                    "content_type": uploaded_file.mimetype
                    or "application/octet-stream",
                    "size": encrypted["size"],
                    "sha256": encrypted["sha256"],
                    "nonce": encrypted["nonce"],
                    "created_at": datetime.now(timezone.utc),
                })
            except Exception:
                storage.delete(stored_id)
                raise

            # Log only after metadata has been stored successfully.
            log_audit_event(
                db,
                current_user.id,
                "file_uploaded",
                str(metadata_id),
            )

        except (ValueError, PyMongoError):
            current_app.logger.exception("Secure file upload failed")
            flash("Upload failed. Please try again.", "error")
            return redirect(url_for("files.upload"))

        except Exception:
            current_app.logger.exception("Unexpected file upload error")
            flash("An unexpected error occurred during upload.", "error")
            return redirect(url_for("files.upload"))

        flash("File encrypted and uploaded successfully.", "success")
        return redirect(url_for("files.my_files"))

    return render_template("upload.html")


@files_bp.route("/files")
@login_required
def my_files():
    db = current_app.extensions.get("mongo_db")

    if db is None:
        flash("Database is unavailable. Please try again.", "error")
        return render_template("my_files.html", files=[]), 503

    owner_id = ObjectId(current_user.id)

    documents = list(
        db.file_metadata.find({
            "owner_id": owner_id
        }).sort("created_at", -1)
    )

    for file in documents:
        active_shares = db.shares.find({
            "file_id": file["_id"],
            "owner_id": owner_id,
            "active": True,
        })

        recipients = []

        for share in active_shares:
            recipient = db.users.find_one(
                {"_id": share["recipient_id"]},
                {"username": 1, "email": 1},
            )

            if recipient:
                recipients.append({
                    "username": recipient.get("username", "Unknown"),
                    "email": recipient["email"],
                    "recipient_id": str(recipient["_id"]),
                })

        file["active_shares"] = recipients

    return render_template("my_files.html", files=documents)


@files_bp.route("/files/download/<file_id>")
@login_required
def download(file_id):
    db = current_app.extensions.get("mongo_db")

    if db is None:
        abort(503)

    try:
        metadata_id = ObjectId(file_id)
        user_id = ObjectId(current_user.id)
    except (InvalidId, TypeError):
        abort(404)

    # Owners can download their own files.
    metadata = db.file_metadata.find_one({
        "_id": metadata_id,
        "owner_id": user_id,
    })

    # Otherwise, check for an active share.
    if metadata is None:
        active_share = db.shares.find_one({
            "file_id": metadata_id,
            "recipient_id": user_id,
            "active": True,
        })

        if active_share is None:
            abort(404)

        metadata = db.file_metadata.find_one({
            "_id": metadata_id,
            "owner_id": active_share["owner_id"],
        })

        if metadata is None:
            abort(404)

    try:
        storage = get_file_storage(db)
        encrypted_file = storage.get(metadata["storage_id"])
        ciphertext = encrypted_file.read()

        master_key = load_master_key(
            current_app.config["MASTER_KEY"]
        )

        original_data = decrypt_file(
            ciphertext,
            metadata["nonce"],
            master_key,
        )

        # Verify the original file's integrity before sending it.
        actual_hash = hashlib.sha256(original_data).hexdigest()

        if not hmac.compare_digest(actual_hash, metadata["sha256"]):
            current_app.logger.warning(
                "File integrity verification failed for %s",
                file_id,
            )
            abort(409, description="File integrity verification failed.")

        log_audit_event(
            db,
            current_user.id,
            "file_downloaded",
            str(metadata_id),
        )

        return send_file(
            BytesIO(original_data),
            mimetype=metadata.get(
                "content_type",
                "application/octet-stream",
            ),
            as_attachment=True,
            download_name=metadata["original_filename"],
        )

    except NoFile:
        current_app.logger.exception("Encrypted file missing from GridFS")
        abort(404)

    except ValueError:
        current_app.logger.exception(
            "File decryption or authentication failed"
        )
        abort(409, description="File could not be securely verified.")

    except HTTPException:
        raise

    except Exception:
        current_app.logger.exception("Unexpected secure download error")
        abort(500)


@files_bp.route("/files/share/<file_id>", methods=["POST"])
@login_required
def share_file(file_id):
    db = current_app.extensions.get("mongo_db")

    if db is None:
        abort(503)

    try:
        metadata_id = ObjectId(file_id)
        owner_id = ObjectId(current_user.id)
    except (InvalidId, TypeError):
        abort(404)

    # Only the owner can share their file.
    metadata = db.file_metadata.find_one({
        "_id": metadata_id,
        "owner_id": owner_id,
    })

    if metadata is None:
        abort(404)

    recipient_email = request.form.get("email", "").strip().lower()

    if not recipient_email:
        flash("Enter the recipient's email address.", "error")
        return redirect(url_for("files.my_files"))

    recipient = db.users.find_one({"email": recipient_email})

    if recipient is None:
        flash("No registered user found with that email.", "error")
        return redirect(url_for("files.my_files"))

    recipient_id = recipient["_id"]

    if recipient_id == owner_id:
        flash("You cannot share a file with yourself.", "error")
        return redirect(url_for("files.my_files"))

    # Re-enable an existing revoked share, or create a new one.
    db.shares.update_one(
        {
            "file_id": metadata_id,
            "owner_id": owner_id,
            "recipient_id": recipient_id,
        },
        {
            "$set": {
                "active": True,
                "updated_at": datetime.now(timezone.utc),
            },
            "$setOnInsert": {
                "created_at": datetime.now(timezone.utc),
            },
        },
        upsert=True,
    )

    log_audit_event(
        db,
        current_user.id,
        "file_shared",
        str(metadata_id),
    )

    flash(
        f"'{metadata['original_filename']}' was shared successfully.",
        "success",
    )
    return redirect(url_for("files.my_files"))


@files_bp.route("/files/shared")
@login_required
def shared_with_me():
    db = current_app.extensions.get("mongo_db")

    if db is None:
        abort(503)

    recipient_id = ObjectId(current_user.id)

    active_shares = db.shares.find({
        "recipient_id": recipient_id,
        "active": True,
    }).sort("created_at", -1)

    shared_files = []

    for share in active_shares:
        metadata = db.file_metadata.find_one({
            "_id": share["file_id"],
            "owner_id": share["owner_id"],
        })

        if metadata is None:
            continue

        owner = db.users.find_one(
            {"_id": share["owner_id"]},
            {"username": 1, "email": 1},
        )

        shared_files.append({
            **metadata,
            "shared_by": owner["username"] if owner else "Unknown user",
            "share_id": share["_id"],
        })

    return render_template(
        "shared_files.html",
        files=shared_files,
    )


@files_bp.route(
    "/files/revoke/<file_id>/<recipient_id>",
    methods=["POST"],
)
@login_required
def revoke_share(file_id, recipient_id):
    db = current_app.extensions.get("mongo_db")

    if db is None:
        abort(503)

    try:
        metadata_id = ObjectId(file_id)
        owner_id = ObjectId(current_user.id)
        target_recipient_id = ObjectId(recipient_id)
    except (InvalidId, TypeError):
        abort(404)

    # Confirm that the file belongs to the current user.
    metadata = db.file_metadata.find_one({
        "_id": metadata_id,
        "owner_id": owner_id,
    })

    if metadata is None:
        abort(404)

    result = db.shares.update_one(
        {
            "file_id": metadata_id,
            "owner_id": owner_id,
            "recipient_id": target_recipient_id,
            "active": True,
        },
        {
            "$set": {
                "active": False,
                "revoked_at": datetime.now(timezone.utc),
            }
        },
    )

    if result.modified_count:
        log_audit_event(
            db,
            current_user.id,
            "share_revoked",
            str(metadata_id),
        )
        flash("File access revoked successfully.", "success")
    else:
        flash("No active share was found to revoke.", "error")

    return redirect(url_for("files.my_files"))


