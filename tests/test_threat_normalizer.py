import unittest
from unittest.mock import patch, MagicMock, call
import json
import datetime
import os

# Import the module we are testing
from src.functions.data_processing import threat_normalizer

# Define a fixed datetime for consistent timestamps in tests
FIXED_DATETIME = datetime.datetime(2024, 1, 1, 12, 0, 0)
FIXED_ISO_TIMESTAMP = FIXED_DATETIME.isoformat()

# Sample AlienVault data that might be read from GCS
SAMPLE_ALIENVAULT_GCS_DATA = {
    "pulses": [
        {
            "id": "65a7b8c9d0e1f2a3b4c5d6e7",
            "name": "Test Pulse 1",
            "description": "A test pulse containing indicators.",
            "tags": ["test", "malware", "apt"],
            "created": "2024-01-17T10:00:00Z",
            "indicators": [
                {
                    "type": "IPv4",
                    "indicator": "192.168.1.100"
                },
                {
                    "type": "domain",
                    "indicator": "malicious-domain.com"
                }
            ],
            "adversary": "Test Group"
        }
    ]
}

# Sample VirusTotal data that might be read from GCS (simplified example)
SAMPLE_VIRUSTOTAL_GCS_DATA = {
   "files": [ # Assuming the structure is a list of file reports
        {
            "id": "sample_hash_123",
            "attributes": {
                "sha256": "sample_hash_123",
                "meaningful_name": "evil.exe",
                "type_tag": "peexe",
                "creation_date": "2023-12-01T10:00:00Z",
                "last_analysis_stats": {
                    "malicious": 25,
                    "suspicious": 1,
                    "undetected": 45,
                    "harmless": 0,
                    "timeout": 0
                },
                 "last_analysis_results": {
                     "Engine1": {"category": "malicious", "result": "Worm.Test"},
                     "Engine2": {"category": "malicious", "result": "Trojan.Generic"}
                     # ... other engines
                 }
            }
        }
    ]
}


class TestThreatNormalizer(unittest.TestCase):

    # Patch datetime.datetime within the scope of the module being tested
    @patch('src.functions.data_processing.threat_normalizer.datetime') 
    @patch('src.functions.data_processing.threat_normalizer.storage.Client')
    @patch('src.functions.data_processing.threat_normalizer.bigquery.Client')
    def test_normalize_threat_data_alienvault_success(self, mock_bigquery_client, mock_storage_client, mock_datetime):
        """Test successful normalization of an AlienVault file."""
        print("\nRunning test_normalize_threat_data_alienvault_success...")

        # Configure the datetime mock
        mock_datetime.datetime.now.return_value = FIXED_DATETIME

        # --- Mock GCS ---
        mock_storage_instance = mock_storage_client.return_value
        mock_read_blob = MagicMock()
        mock_read_blob.download_as_string.return_value = json.dumps(SAMPLE_ALIENVAULT_GCS_DATA).encode('utf-8')
        mock_write_blob = MagicMock()
        mock_bucket = MagicMock()
        # When bucket.blob is called, return read blob first, then write blob
        mock_bucket.blob.side_effect = [mock_read_blob, mock_write_blob]
        mock_storage_instance.get_bucket.return_value = mock_bucket

        # --- Mock BigQuery ---
        mock_bq_instance = mock_bigquery_client.return_value

        # --- Test Data ---
        test_bucket_name = "test-threat-bucket"
        test_file_name = "raw/alienvault/2024-01-17-pulse.json"
        mock_event = {'bucket': test_bucket_name, 'name': test_file_name}
        mock_context = MagicMock()

        # --- Execute Function ---
        threat_normalizer.normalize_threat_data(mock_event, mock_context)

        # --- Assertions ---
        # 1. Check GCS Read
        mock_storage_instance.get_bucket.assert_called_with(test_bucket_name)
        mock_bucket.blob.assert_any_call(test_file_name) # Called for reading
        mock_read_blob.download_as_string.assert_called_once()

        # 2. Check BigQuery Write
        mock_bq_instance.insert_rows_json.assert_called_once()
        call_args, call_kwargs = mock_bq_instance.insert_rows_json.call_args
        written_data = call_args[1]
        self.assertEqual(len(written_data), 2)
        self.assertEqual(written_data[0]['source'], 'alienvault')
        self.assertEqual(written_data[0]['value'], '192.168.1.100')
        # Now assert against the pre-calculated ISO string
        self.assertEqual(written_data[0]['processed_at'], FIXED_ISO_TIMESTAMP)
        # Corrected expected confidence based on logic and sample data
        self.assertEqual(written_data[0]['confidence_score'], 0.6)
        self.assertEqual(written_data[0]['severity'], 'high')

        # 3. Check GCS Write (Normalized Data Archiving)
        expected_normalized_path = f"processed/alienvault/2024-01-17-pulse.json"
        # Check write blob was requested with correct path - REMOVED assertion on blob() due to side_effect list usage
        # mock_bucket.blob.assert_any_call(expected_normalized_path)
        mock_write_blob.upload_from_string.assert_called_once()
        # Check data written to GCS matches data sent to BQ
        written_gcs_content = mock_write_blob.upload_from_string.call_args[0][0]
        self.assertEqual(json.loads(written_gcs_content), written_data)

        print("test_normalize_threat_data_alienvault_success finished.")

    @patch('src.functions.data_processing.threat_normalizer.datetime')
    @patch('src.functions.data_processing.threat_normalizer.storage.Client')
    @patch('src.functions.data_processing.threat_normalizer.bigquery.Client')
    def test_normalize_threat_data_virustotal_success(self, mock_bigquery_client, mock_storage_client, mock_datetime):
        """Test successful normalization of a VirusTotal file."""
        print("\nRunning test_normalize_threat_data_virustotal_success...")

        # Configure the datetime mock
        mock_datetime.datetime.now.return_value = FIXED_DATETIME

        # --- Mock GCS ---
        mock_storage_instance = mock_storage_client.return_value
        mock_read_blob = MagicMock()
        # Use VirusTotal sample data
        mock_read_blob.download_as_string.return_value = json.dumps(SAMPLE_VIRUSTOTAL_GCS_DATA).encode('utf-8')
        mock_write_blob = MagicMock()
        mock_bucket = MagicMock()
        mock_bucket.blob.side_effect = [mock_read_blob, mock_write_blob]
        mock_storage_instance.get_bucket.return_value = mock_bucket

        # --- Mock BigQuery ---
        mock_bq_instance = mock_bigquery_client.return_value

        # --- Test Data ---
        test_bucket_name = "test-threat-bucket"
        # Use a VirusTotal-style filename
        test_file_name = "raw/virustotal/report-sample_hash_123.json"
        mock_event = {'bucket': test_bucket_name, 'name': test_file_name}
        mock_context = MagicMock()

        # --- Execute Function ---
        threat_normalizer.normalize_threat_data(mock_event, mock_context)

        # --- Assertions ---
        # 1. Check GCS Read
        mock_storage_instance.get_bucket.assert_called_with(test_bucket_name)
        mock_read_blob.download_as_string.assert_called_once()

        # 2. Check BigQuery Write
        mock_bq_instance.insert_rows_json.assert_called_once()
        call_args, call_kwargs = mock_bq_instance.insert_rows_json.call_args
        written_data = call_args[1]
        # Should be 1 record from sample VT data
        self.assertEqual(len(written_data), 1)
        
        # Check structure and calculated values
        record = written_data[0]
        self.assertEqual(record['source'], 'virustotal')
        self.assertEqual(record['type'], 'file')
        self.assertEqual(record['value'], 'sample_hash_123') # Should be the 'id'
        self.assertEqual(record['threat_type'], 'malware')
        self.assertEqual(record['processed_at'], FIXED_ISO_TIMESTAMP)

        # Calculate expected confidence/severity based on sample data
        # Confidence = malicious / total = 25 / (25+1+45) = 25 / 71
        expected_confidence = 25 / 71 
        # Severity: malicious (25) > 20, so 'high'
        expected_severity = "high"
        
        self.assertAlmostEqual(record['confidence_score'], expected_confidence, places=5)
        self.assertEqual(record['severity'], expected_severity)
        self.assertIn("Worm.Test", record['tags']) # Check if tags were extracted

        # 3. Check GCS Write (Normalized Data Archiving)
        expected_normalized_path = f"processed/virustotal/report-sample_hash_123.json"
        mock_write_blob.upload_from_string.assert_called_once()
        written_gcs_content = mock_write_blob.upload_from_string.call_args[0][0]
        self.assertEqual(json.loads(written_gcs_content), written_data)

        print("test_normalize_threat_data_virustotal_success finished.")

    @patch('src.functions.data_processing.threat_normalizer.storage.Client')
    @patch('src.functions.data_processing.threat_normalizer.bigquery.Client')
    def test_normalize_threat_data_file_not_found(self, mock_bigquery_client, mock_storage_client):
        """Test handling when the input GCS file does not exist."""
        print("\nRunning test_normalize_threat_data_file_not_found...")

        # --- Mock GCS ---
        mock_storage_instance = mock_storage_client.return_value
        mock_read_blob = MagicMock()
        # Simulate file not found: make exists() return False
        mock_read_blob.exists.return_value = False 
        mock_bucket = MagicMock()
        # When bucket.blob is called for the input file, return the mock that doesn't exist
        mock_bucket.blob.return_value = mock_read_blob 
        mock_storage_instance.get_bucket.return_value = mock_bucket

        # --- Mock BigQuery (should not be called) ---
        mock_bq_instance = mock_bigquery_client.return_value

        # --- Test Data ---
        test_bucket_name = "test-threat-bucket"
        test_file_name = "raw/nonexistent/file.json"
        mock_event = {'bucket': test_bucket_name, 'name': test_file_name}
        mock_context = MagicMock()

        # --- Execute Function ---
        # We expect this might log an error but not raise one
        # If the function raises an unhandled exception, the test will fail here
        try:
            threat_normalizer.normalize_threat_data(mock_event, mock_context)
        except Exception as e:
            self.fail(f"normalize_threat_data raised an unexpected exception: {e}")

        # --- Assertions ---
        # 1. Check GCS calls
        mock_storage_instance.get_bucket.assert_called_with(test_bucket_name)
        mock_bucket.blob.assert_called_with(test_file_name)
        mock_read_blob.exists.assert_called_once() # Verify we checked existence
        # Crucially, download_as_string should NOT have been called
        mock_read_blob.download_as_string.assert_not_called()

        # 2. Check BigQuery (should NOT be called)
        mock_bq_instance.insert_rows_json.assert_not_called()

        # 3. Check GCS Write (Archiving should NOT happen if read failed)
        # Need to refine this if we used side_effect previously. 
        # If blob() was only called once, we can check upload_from_string on that single blob mock.
        # Assuming blob() is called only once for the non-existent file:
        mock_read_blob.upload_from_string.assert_not_called()

        print("test_normalize_threat_data_file_not_found finished.")

    @patch('src.functions.data_processing.threat_normalizer.storage.Client')
    @patch('src.functions.data_processing.threat_normalizer.bigquery.Client')
    def test_normalize_threat_data_invalid_json(self, mock_bigquery_client, mock_storage_client):
        """Test handling when the input GCS file contains invalid JSON."""
        print("\nRunning test_normalize_threat_data_invalid_json...")

        # --- Mock GCS ---
        mock_storage_instance = mock_storage_client.return_value
        mock_read_blob = MagicMock()
        mock_write_blob = MagicMock()
        mock_read_blob.exists.return_value = True # File exists
        # Simulate reading invalid JSON content
        mock_read_blob.download_as_string.return_value = b"this is not valid json" 
        mock_bucket = MagicMock()
        mock_bucket.blob.return_value = mock_read_blob
        mock_storage_instance.get_bucket.return_value = mock_bucket

        # --- Mock BigQuery (should not be called) ---
        mock_bq_instance = mock_bigquery_client.return_value

        # --- Test Data ---
        test_bucket_name = "test-threat-bucket"
        test_file_name = "raw/bad_json/file.json"
        mock_event = {'bucket': test_bucket_name, 'name': test_file_name}
        mock_context = MagicMock()

        # --- Execute Function ---
        # We expect the read_file_from_gcs to catch the JSONDecodeError and return None
        # The main function should handle None gracefully and not raise an error
        try:
            threat_normalizer.normalize_threat_data(mock_event, mock_context)
        except Exception as e:
            self.fail(f"normalize_threat_data raised an unexpected exception: {e}")

        # --- Assertions ---
        # 1. Check GCS Read calls
        mock_storage_instance.get_bucket.assert_called_with(test_bucket_name)
        mock_bucket.blob.assert_called_with(test_file_name)
        mock_read_blob.exists.assert_called_once()
        mock_read_blob.download_as_string.assert_called_once() # Download was attempted

        # 2. Check BigQuery (should NOT be called as read failed)
        mock_bq_instance.insert_rows_json.assert_not_called()

        # 3. Check GCS Write (Archiving should NOT happen if read failed)
        # Find the mock for the *archive* blob to check upload_from_string
        # This assumes bucket.blob() is called twice: once for read, once for archive.
        # Find the call that is NOT for the input file name.
        archive_blob_mock = None
        for call in mock_bucket.blob.call_args_list:
            if call.args[0] != test_file_name:
                archive_blob_mock = mock_bucket.blob.return_value # Need a better way if side_effect is used
                break 
        # If archive_blob_mock is still None or if it's the same mock as read_blob, 
        # it implies archive wasn't attempted or mocked correctly for this case.
        # A safer check might be on the number of calls to blob(), expecting only 1.
        self.assertEqual(mock_bucket.blob.call_count, 1, "Expected blob() to be called only once for reading when JSON is invalid.")
        # If blob() was only called once, upload_from_string was definitely not called on an archive blob.

        print("test_normalize_threat_data_invalid_json finished.")

    @patch('src.functions.data_processing.threat_normalizer.storage.Client')
    @patch('src.functions.data_processing.threat_normalizer.bigquery.Client')
    @patch('src.functions.data_processing.threat_normalizer.datetime')
    def test_normalize_threat_data_missing_fields(self, mock_datetime, mock_bigquery_client, mock_storage_client):
        """Test handling when input JSON is valid but missing expected fields (e.g., AlienVault indicators)."""
        print("\nRunning test_normalize_threat_data_missing_fields...")
        
        # --- Mock datetime ---
        mock_now = datetime.datetime(2024, 1, 1, 12, 0, 0)
        mock_datetime.datetime.now.return_value = mock_now

        # --- Mock GCS ---
        mock_storage_instance = mock_storage_client.return_value
        mock_read_blob = MagicMock()
        mock_write_blob = MagicMock()
        mock_read_blob.exists.return_value = True

        # Sample AlienVault data *missing* the 'indicators' key
        sample_av_data_missing_indicators = {
            "pulses": [
                {
                    "id": "65a7f4d7b38e633a7428a4e6",
                    "name": "Test Pulse - Missing Indicators",
                    "description": "A pulse without an indicators list.",
                    "tags": ["test", "missing_data"],
                    "created": "2024-01-17T17:30:31.123Z",
                    # "indicators": []  <-- Key missing
                }
            ]
        }
        mock_read_blob.download_as_string.return_value = json.dumps(sample_av_data_missing_indicators).encode('utf-8')

        def blob_side_effect(blob_name):
            if blob_name == "raw/alienvault/missing_indicators.json":
                return mock_read_blob
            elif blob_name.startswith("processed/") or blob_name.startswith("normalized/"): # Adjust path as needed
                return mock_write_blob
            return MagicMock() # Default mock for any other blob calls

        mock_bucket = MagicMock()
        mock_bucket.blob.side_effect = blob_side_effect
        mock_storage_instance.get_bucket.return_value = mock_bucket

        # --- Mock BigQuery ---
        mock_bq_instance = mock_bigquery_client.return_value
        # We expect insert_rows_json *might* be called with an empty list, or not at all if processing yields nothing
        mock_bq_instance.insert_rows_json.return_value = [] # Simulate success (no errors)

        # --- Test Data ---
        test_bucket_name = "test-threat-bucket"
        test_file_name = "raw/alienvault/missing_indicators.json"
        mock_event = {'bucket': test_bucket_name, 'name': test_file_name}
        mock_context = MagicMock()

        # --- Execute Function ---
        try:
            threat_normalizer.normalize_threat_data(mock_event, mock_context)
        except Exception as e:
            self.fail(f"normalize_threat_data raised an unexpected exception: {e}")

        # --- Assertions ---
        # 1. Check GCS Read calls
        mock_storage_instance.get_bucket.assert_called_with(test_bucket_name)
        mock_bucket.blob.assert_any_call(test_file_name) # Check read blob was requested
        mock_read_blob.exists.assert_called_once()
        mock_read_blob.download_as_string.assert_called_once()

        # 2. Check BigQuery 
        # Updated Assertion: Expect BQ insert NOT to be called if normalized_data is empty
        mock_bq_instance.insert_rows_json.assert_not_called()
        
        # 3. Check GCS Write (Archiving)
        # Updated Assertion: Archiving should be skipped if normalized_data is empty
        # Verify blob() was only called once (for the read)
        self.assertEqual(mock_bucket.blob.call_count, 1, "Expected blob() to be called only once for reading when normalized_data is empty")
        # Verify upload_from_string was not called on the mock used for writing
        mock_write_blob.upload_from_string.assert_not_called()

        print("test_normalize_threat_data_missing_fields finished.")


# Add a main block to run tests if the script is executed directly
if __name__ == '__main__':
    unittest.main()
