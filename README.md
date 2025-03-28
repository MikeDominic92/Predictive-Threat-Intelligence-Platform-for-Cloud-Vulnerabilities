# Predictive Threat Intelligence Platform for Cloud Vulnerabilities

This project which aims to create a proactive threat intelligence platform for cloud environments. My goal is to move beyond just reacting to security issues and explore ways to predict emerging threats before they hit.

## Project Vision

I believe that staying secure in the cloud today means being predictive, not just reactive. I'm designing this platform to use machine learning and data analysis to spot patterns in threat data—patterns that might point to the next big vulnerability or attack vector *before* it happens.

Most threat platforms react after the fact. With this project, I'm exploring how to shift that towards prediction. It feels essential for keeping up with the speed of cloud threats.

## Conceptual Approach

I'm designing the platform with a few key capabilities in mind:

- Aggregating and normalizing data from diverse threat intelligence sources
- Using NLP techniques to extract insights from unstructured text in security advisories
- Applying time series analysis to identify trends in vulnerability disclosures and exploits
- Implementing machine learning to predict which vulnerabilities may be targeted

My hope is that this approach will help security teams prioritize based on what's likely to happen next, not just what's happened already. I'm interested to see how this could strengthen cloud security.

## Proposed Architecture

The platform design includes these main parts:

### Data Ingestion Layer
This layer will collect data from various threat intelligence sources, including open-source feeds (like AlienVault OTX, VirusTotal), vendor security advisories, research papers, and security blogs.

**Implementation:** The initial data collection is handled by the `osint_collector` Google Cloud Function (`src/functions/osint_collector`), which currently gathers:
  - Pulses from AlienVault OTX.
  - IP Address reports from VirusTotal.
Data is saved in JSON format to Google Cloud Storage (`raw/alienvault/` and `raw/virustotal/` prefixes).

### Data Processing Pipeline
A cloud-native pipeline will normalize and enrich the raw intelligence data, getting it ready for analysis.

### ML Analysis Engine
This is where the core analysis happens, using techniques like:
- NLP processing to extract meaningful insights from unstructured text
- Time series analysis for identifying patterns in threat data
- Classification models for predicting vulnerability exploitation likelihood

### Visualization & Insights
A dashboard (likely using Grafana) will display the predicted threats and potential mitigations clearly.

## Potential Technologies

I'm planning to use technologies like these:

- Google Cloud Platform (GCP) infrastructure
- Cloud Storage for the data lake
- BigQuery for data warehousing and analysis
- Vertex AI for the machine learning parts
- Terraform for managing the infrastructure as code
- Grafana for the visualization dashboard

## Current State & Next Steps

This repository contains the architectural plans and design concepts for the platform. I'm working to implement proof-of-concept modules for the key components, starting with the data collection and processing pipeline.

**Update:** The `osint_collector` Google Cloud Function for collecting data from AlienVault OTX and VirusTotal (IP reports) has been implemented and deployed. Raw data is being saved to Google Cloud Storage.

This is an ongoing project meant to demonstrate cloud security concepts and explore the potential of AI/ML in predictive threat intelligence.

## Learning Goals

Through this project, I'm working to develop and demonstrate:

1. Cloud-native security architecture design
2. Data engineering for security intelligence
3. Applying machine learning to cybersecurity problems
4. Infrastructure as code for security systems
5. Effective visualization of complex security data

## Development & Testing

### Testing
I've set up unit tests for the `threat_normalizer` function, which you can find in `src/functions/data_processing/threat_normalizer.py`. The goal of these tests is to make sure the data normalization logic works correctly for the different threat intelligence sources I'm using.

#### Setup

The tests are written using Python's standard `unittest` framework and the `unittest.mock` library. I'm using mocking to test the function in isolation, without needing to connect to real external services. Here's what I mock:

- **Google Cloud Storage (`google.cloud.storage.Client`):** This is mocked to simulate reading the raw data files, like AlienVault pulses or VirusTotal reports, and also to simulate writing the processed data files back to storage. This avoids needing a real GCS connection during tests.

- **Google BigQuery (`google.cloud.bigquery.Client`):** This is mocked so I can check that the function tries to insert the correctly structured normalized data into BigQuery, again without needing a live connection.

- **Datetime (`datetime.datetime`):** I mock this to get a consistent timestamp (for the `processed_at` field) in the tests, making it easier to check the output.

Inside `tests/test_threat_normalizer.py`, I've included sample JSON data that mimics typical input from AlienVault and VirusTotal.

#### Running the Tests

To run these tests yourself, open a terminal, go to the main project directory (`predictive-threat-intelligence`), and run this command:

```bash
python -m unittest discover tests
```

#### Test Output Example

When you run the tests, the output looks something like this (I've snipped some of the noisy mock object details):

```text
ss...
Running test_normalize_threat_data_alienvault_success...
Processing alienvault data from raw/alienvault/2024-01-17-pulse.json
Errors inserting rows to BigQuery: <MagicMock name='Client().insert_rows_json()' id='...'>
Processed 2 threat indicators from alienvault
Archived normalized data to test-threat-bucket/processed/alienvault/2024-01-17-pulse.json
test_normalize_threat_data_alienvault_success finished.

Running test_normalize_threat_data_virustotal_success...
Processing virustotal data from raw/virustotal/report-sample_hash_123.json
Errors inserting rows to BigQuery: <MagicMock name='Client().insert_rows_json()' id='...'>
Processed 1 threat indicators from virustotal
Archived normalized data to test-threat-bucket/normalized/virustotal/report-sample_hash_123.json
test_normalize_threat_data_virustotal_success finished.

-----------------------------------------------------------------------
Ran 5 tests in 0.004s

OK (skipped=2)
```

#### Understanding the Output

The `OK` at the end confirms that the tests I wrote passed their checks. The print messages show the function attempting steps like processing indicators and writing data using the mocked clients. That "Errors inserting rows..." message just shows the mocked BigQuery client was called, which is exactly what I want to verify in the test—the tests check *what* data was sent to the mock.

The summary line showing `skipped=2` is also expected. These skipped tests (`test_collect_from_alienvault_live` and `test_collect_from_virustotal_live` in `tests/test_osint_collector.py`) are designed for live API testing and require credentials/network access, so they are correctly skipped during standard unit test runs focused on isolated logic.

### OSINT Collector Testing
The `osint_collector` function was tested manually through:
1. Local execution using `functions-framework` (run in the foreground to view logs/errors).
2. Triggering via `curl` locally.
3. Verifying output files in Google Cloud Storage.
4. Deploying to Cloud Functions and testing via Pub/Sub trigger, checking Cloud Function logs and GCS output.

## Getting Started

The `/docs` folder contains detailed architectural diagrams and design documents that outline the platform concept.

*Note: This is a portfolio project to showcase architectural thinking and cloud security concepts. Implementation is ongoing.*

## Deployment

Deployment uses Terraform Cloud for managing infrastructure and Google Cloud Build for deploying the Cloud Function code.

### OSINT Collector Deployment (`osint_collector`)

The `osint_collector` function is deployed as a Google Cloud Function (Gen 2).

- **Deployment Command:** Uses `gcloud functions deploy ...` (see command history or documentation for exact flags).
- **Trigger:** Pub/Sub topic (e.g., `osint-collection-trigger`).
- **Required APIs:** Cloud Functions, Cloud Build, Eventarc, Pub/Sub, Cloud Storage.
- **Required Environment Variables:** See the section below.

### Environment Variables

The following environment variables are required for the project components:

**`osint_collector` Function:**
- `OTX_API_KEY`: Your AlienVault OTX API key.
- `VT_API_KEY`: Your VirusTotal API key.
- `GCS_RAW_BUCKET`: The name of the Google Cloud Storage bucket where raw collected data will be saved (e.g., `your-gcs-bucket-name`).

*(Add variables for other components like `threat_normalizer` as they are implemented)*

### Project Structure

- `main.py`: Contains the Cloud Function entry point (`normalize_threat_data`).
- `src/functions/data_processing/threat_normalizer.py`: Main logic, including GCS/BigQuery interaction and specific format handling (currently within this file).
- `utils.py`: Helper functions (e.g., GCS/BigQuery interaction, timestamping).
- `requirements.txt`: Python dependencies.
- `src/functions/osint_collector/main.py`: Cloud Function entry point (`collect_osint_data`), logic for fetching data from AlienVault/VirusTotal and saving to GCS.
- `src/functions/osint_collector/requirements.txt`: Python dependencies for the collector (`google-cloud-storage`, `requests`, `functions-framework`, `python-dotenv`).

## License

MIT
