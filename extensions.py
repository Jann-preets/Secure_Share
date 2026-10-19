
from flask import current_app
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from bson import ObjectId
from bson.errors import InvalidId

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "info"

csrf = CSRFProtect()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
)


@login_manager.user_loader
def load_user(user_id):
    db = current_app.extensions.get("mongo_db")

    if db is None:
        return None

    try:
        document = db.users.find_one({
            "_id": ObjectId(user_id)
        })
    except (InvalidId, TypeError):
        return None

    if document is None:
        return None

    from security.user import User
    return User.from_document(document)
