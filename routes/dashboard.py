
from bson import ObjectId
from flask import Blueprint, current_app, render_template
from flask_login import login_required, current_user

dashboard = Blueprint("dashboard", __name__)


@dashboard.route("/dashboard")
@login_required
def index():
    db = current_app.extensions.get("mongo_db")

    stats = {
        "total_files": 0,
        "shared_files": 0,
        "recent_activity": 0,
    }

    activities = []

    if db is not None:
        owner_id = ObjectId(current_user.id)

        # Summary statistics
        stats["total_files"] = db.file_metadata.count_documents({
            "owner_id": owner_id,
        })

        stats["shared_files"] = db.shares.count_documents({
            "owner_id": owner_id,
            "active": True,
        })

        stats["recent_activity"] = db.audit_logs.count_documents({
            "user_id": owner_id,
        })

        # Fetch the five latest actions performed by this user.
        recent_logs = db.audit_logs.find({
            "user_id": owner_id,
        }).sort("timestamp", -1).limit(5)

        action_labels = {
            "file_uploaded": "Uploaded a file",
            "file_downloaded": "Downloaded a file",
            "file_shared": "Shared a file",
            "share_revoked": "Revoked file access",
        }

        for log in recent_logs:
            file_name = "Unknown file"
            file_id = log.get("file_id")

            if file_id:
                metadata = db.file_metadata.find_one(
                    {"_id": file_id, "owner_id": owner_id},
                    {"original_filename": 1},
                )

                # Shared files may belong to another user.
                if metadata is None:
                    metadata = db.file_metadata.find_one(
                        {"_id": file_id},
                        {"original_filename": 1},
                    )

                if metadata:
                    file_name = metadata.get(
                        "original_filename",
                        "Unknown file",
                    )

            activities.append({
                "action": action_labels.get(
                    log.get("action"),
                    log.get("action", "Unknown action"),
                ),
                "file_name": file_name,
                "timestamp": log.get("timestamp"),
            })

    return render_template(
        "dashboard.html",
        stats=stats,
        activities=activities,
        db_status=current_app.extensions.get(
            "mongo_status",
            "Unknown",
        ),
    )
