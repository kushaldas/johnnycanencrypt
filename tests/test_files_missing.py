import pytest
import johnnycanencrypt as jce


def test_missing_key():
    with pytest.raises(FileNotFoundError):
        j = jce.Johnny("missingfile.asc")
