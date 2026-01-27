from unittest.mock import patch, MagicMock, PropertyMock
from pathlib import Path
import pytest
from googlethreatintelligence.scan_file import GTIScanFile
import vt

API_KEY = "FAKE_API_KEY"


def _create_file_in_data_storage(data_storage: Path, rel_path: str, content: bytes = b"dummy content") -> Path:
    abs_path = data_storage.joinpath(rel_path)
    abs_path.parent.mkdir(parents=True, exist_ok=True)
    abs_path.write_bytes(content)
    return abs_path


# === SUCCESS CASE ===
@patch("googlethreatintelligence.scan_file.vt.Client")
@patch("googlethreatintelligence.scan_file.VTAPIConnector")
@patch("googlethreatintelligence.scan_file.copy_to_tempfile")
def test_scan_file_success(mock_copy, mock_connector_class, mock_vt_client, data_storage, module):
    """Test successful file scan"""

    rel_path = "samples/dummy.bin"
    _create_file_in_data_storage(data_storage, rel_path)

    # Mock copy_to_tempfile context manager
    tmp_path = "/tmp/fake_tmp_dir/dummy.bin"
    mock_copy.return_value.__enter__ = MagicMock(return_value=tmp_path)
    mock_copy.return_value.__exit__ = MagicMock(return_value=False)

    # Mock VTAPIConnector instance
    mock_connector_instance = MagicMock()
    mock_connector_class.return_value = mock_connector_instance

    # Mock the results list - scan_file() appends to this list
    mock_result = MagicMock()
    mock_result.response = {
        "analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 50},
        "analysis_results": {"scanner1": "clean", "scanner2": "clean"},
    }
    mock_connector_instance.results = [mock_result]
    mock_connector_instance.scan_file.return_value = None

    # Mock vt.Client context manager
    mock_client_instance = MagicMock()
    mock_vt_client.return_value.__enter__.return_value = mock_client_instance

    # Initialize action and mock configuration
    action = GTIScanFile(module=module, data_path=data_storage)
    action.module.configuration = {"api_key": API_KEY}

    # Run the action with RELATIVE path (prod behavior)
    response = action.run({"file_path": rel_path})

    assert response is not None
    assert response["success"] is True
    assert "data" in response
    assert response["data"]["analysis_stats"]["malicious"] == 0
    assert "analysis_results" in response["data"]
    assert response["data"]["file_path"] == rel_path  # we default to rel_path

    mock_connector_class.assert_called_once_with(API_KEY, url="", domain="", ip="", file_hash="", cve="")
    mock_connector_instance.scan_file.assert_called_once_with(mock_client_instance, tmp_path)
    mock_vt_client.assert_called_once_with(API_KEY, trust_env=True)


# === MISSING API KEY ===
def test_scan_file_no_api_key(data_storage, module):
    """Test behavior when API key is missing"""
    action = GTIScanFile(module=module, data_path=data_storage)

    # Mock module.configuration PropertyMock
    with patch.object(type(action.module), "configuration", new_callable=PropertyMock) as mock_config:
        mock_config.return_value = {}

        response = action.run({"file_path": "samples/dummy.bin"})

        assert response is not None
        assert response["success"] is False
        assert "API key" in response["error"]


# === FILE NOT FOUND (relative path not present in DATA_STORAGE) ===
def test_scan_file_file_not_found(data_storage, module):
    """Test behavior when the file does not exist in DATA_STORAGE"""
    action = GTIScanFile(module=module, data_path=data_storage)
    action.module.configuration = {"api_key": API_KEY}

    with pytest.raises(FileNotFoundError):
        action.run({"file_path": "samples/does_not_exist.bin"})


# === API ERROR HANDLING ===
@patch("googlethreatintelligence.scan_file.vt.Client")
@patch("googlethreatintelligence.scan_file.VTAPIConnector")
@patch("googlethreatintelligence.scan_file.copy_to_tempfile")
def test_scan_file_api_error(mock_copy, mock_connector_class, mock_vt_client, data_storage, module):
    """Test behavior when the VirusTotal API fails"""
    rel_path = "samples/dummy.bin"
    _create_file_in_data_storage(data_storage, rel_path)

    # Mock copy_to_tempfile
    tmp_path = "/tmp/fake_tmp_dir/dummy.bin"
    mock_copy.return_value.__enter__ = MagicMock(return_value=tmp_path)
    mock_copy.return_value.__exit__ = MagicMock(return_value=False)

    # Mock connector that raises an APIError
    mock_connector_instance = MagicMock()
    mock_connector_instance.scan_file.side_effect = vt.APIError("QuotaExceededError", "API quota exceeded")
    mock_connector_class.return_value = mock_connector_instance

    # Mock vt.Client context
    mock_client_instance = MagicMock()
    mock_vt_client.return_value.__enter__.return_value = mock_client_instance

    action = GTIScanFile(module=module, data_path=data_storage)
    action.module.configuration = {"api_key": API_KEY}

    with pytest.raises(vt.APIError):
        action.run({"file_path": rel_path})

    mock_connector_instance.scan_file.assert_called_once_with(mock_client_instance, tmp_path)
    mock_vt_client.assert_called_once_with(API_KEY, trust_env=True)


# === EDGE CASE: Empty results list ===
@patch("googlethreatintelligence.scan_file.vt.Client")
@patch("googlethreatintelligence.scan_file.VTAPIConnector")
@patch("googlethreatintelligence.scan_file.copy_to_tempfile")
def test_scan_file_empty_results(mock_copy, mock_connector_class, mock_vt_client, data_storage, module):
    """Test behavior when connector.results is empty (edge case)"""
    rel_path = "samples/dummy.bin"
    _create_file_in_data_storage(data_storage, rel_path)

    # Mock copy_to_tempfile
    tmp_path = "/tmp/fake_tmp_dir/dummy.bin"
    mock_copy.return_value.__enter__ = MagicMock(return_value=tmp_path)
    mock_copy.return_value.__exit__ = MagicMock(return_value=False)

    mock_connector_instance = MagicMock()
    mock_connector_instance.results = []  # Empty results list
    mock_connector_instance.scan_file.return_value = None
    mock_connector_class.return_value = mock_connector_instance

    mock_client_instance = MagicMock()
    mock_vt_client.return_value.__enter__.return_value = mock_client_instance

    action = GTIScanFile(module=module, data_path=data_storage)
    action.module.configuration = {"api_key": API_KEY}

    response = action.run({"file_path": rel_path})

    assert response is not None
    assert response["success"] is False
    assert "error" in response
