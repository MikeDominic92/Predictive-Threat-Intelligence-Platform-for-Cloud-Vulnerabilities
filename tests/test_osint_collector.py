# Tests for osint_collector.py
import unittest
import os
import sys

# Add the src directory to the Python path to import the collector module
# Adjust the path as necessary based on your project structure
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
src_path = os.path.join(project_root, '..', 'predictive-threat-intelligence', 'src', 'functions', 'data_ingestion')
sys.path.insert(0, src_path)

# Now try importing the module
try:
    # Assuming the file is osint_collector.py and functions are defined within it
    from osint_collector import collect_from_alienvault, collect_from_virustotal
except ImportError as e:
    print(f"Error importing osint_collector: {e}")
    print(f"Please ensure the path '{src_path}' is correct and contains 'osint_collector.py'")
    # Provide a dummy class to avoid fatal errors if import fails, allowing other tests to potentially run
    class DummyCollector:
        def collect_from_alienvault(self): pass
        def collect_from_virustotal(self): pass
    collector_module = DummyCollector()
    collect_from_alienvault = collector_module.collect_from_alienvault
    collect_from_virustotal = collector_module.collect_from_virustotal


class TestOsintCollectorLive(unittest.TestCase):

    @unittest.skipIf(not os.environ.get("ALIENVAULT_API_KEY"), "ALIENVAULT_API_KEY environment variable not set")
    def test_collect_from_alienvault_live(self):
        """Test collecting data from AlienVault OTX API live."""
        print("\nTesting AlienVault OTX API...")
        result = collect_from_alienvault()
        print(f"AlienVault Result: {result}")

        self.assertNotIn("error", result, f"AlienVault collection failed: {result.get('error')}")
        self.assertIn("pulses", result)
        self.assertIn("count", result)
        self.assertIsInstance(result["pulses"], list)
        self.assertGreaterEqual(result["count"], 0)
        self.assertTrue(result["count"] == len(result["pulses"]))

    @unittest.skipIf(not os.environ.get("VIRUSTOTAL_API_KEY"), "VIRUSTOTAL_API_KEY environment variable not set")
    def test_collect_from_virustotal_live(self):
        """Test collecting data from VirusTotal API live using /files endpoint."""
        print("\nTesting VirusTotal API (/files endpoint)...")
        result = collect_from_virustotal()
        print(f"VirusTotal Result: {result}")

        # Check for specific errors like 404 which might be expected if the hash isn't found (though EICAR should be)
        if "error" in result and result.get("status_code") == 404:
             self.fail(f"VirusTotal collection reported hash not found (404), which is unexpected for EICAR: {result}")
        
        # General error check
        self.assertNotIn("error", result, f"VirusTotal collection failed: {result.get('error')} - {result.get('details')}")
        
        # Check for expected keys from the /files endpoint
        self.assertIn("report", result)
        self.assertIn("hash", result)
        self.assertIsInstance(result["report"], dict) # The report attributes should be a dict
        self.assertEqual(result["hash"], "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        # Optionally, check for a specific field within the report if it's guaranteed to exist
        # self.assertIn("last_analysis_stats", result["report"])

# TODO: Add test cases for the main collect_osint function (needs mocking for Pub/Sub and GCS)
# TODO: Add test cases for save_to_storage (needs mocking for GCS)

if __name__ == "__main__":
    unittest.main()
