
from gridfs import GridFS
from pymongo.database import Database


def get_file_storage(db: Database) -> GridFS:
    """Return the GridFS bucket used for encrypted files."""
    return GridFS(db, collection="encrypted_files")
