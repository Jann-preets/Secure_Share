
from unittest.mock import patch

from services.storage import get_file_storage


def test_gridfs_storage_uses_expected_collection():
    fake_db = object()

    with patch("services.storage.GridFS") as mock_gridfs:
        get_file_storage(fake_db)

        mock_gridfs.assert_called_once_with(
            fake_db,
            collection="encrypted_files",
        )
