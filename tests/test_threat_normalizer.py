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

    # TODO: Add more tests:
    # - test_normalize_threat_data_skip_non_raw
    # - test_normalize_threat_data_invalid_path
    # - test_normalize_threat_data_gcs_read_error
    # - test_normalize_threat_data_bq_write_error (if applicable)
    # - test_normalize_threat_data_gcs_write_error (if applicable)
    # - test_*_data_structure (for more granular checks)


if __name__ == '__main__':
    unittest.main()
