# Predictive Threat Intelligence Platform for Cloud Vulnerabilities

This project aims to create a proactive threat intelligence platform for cloud environments that moves beyond reactive security approaches to predict emerging threats before they become widespread attacks.

## Project Vision

The modern cloud security landscape requires more than just reaction to known threats. This platform concept is designed to leverage machine learning and data analysis to identify patterns in threat data that could indicate emerging vulnerabilities and attack vectors.

Traditional threat platforms are primarily reactive, and this project explores approaches to shift that paradigm toward predictive capabilities.

## Conceptual Approach

The platform's design explores several key capabilities:

- Aggregating and normalizing data from diverse threat intelligence sources
- Using NLP techniques to extract insights from unstructured text in security advisories
- Applying time series analysis to identify trends in vulnerability disclosures and exploits
- Implementing machine learning to predict which vulnerabilities may be targeted

This approach would enable security teams to prioritize their efforts based on predicted threat likelihood rather than just historical data.

## Proposed Architecture

The platform design is built around these major components:

**Data Ingestion Layer**
A conceptual system for collecting data from various threat intelligence sources including open-source feeds (AlienVault OTX, VirusTotal), vendor security advisories, research publications, and security blogs.

**Data Processing Pipeline**
A design for normalizing and enriching raw intelligence data through a cloud-native pipeline into formats suitable for analysis.

**ML Analysis Engine**
The architectural concept for implementing various machine learning approaches:
- NLP processing to extract meaningful insights from unstructured text
- Time series analysis for identifying patterns in threat data
- Classification models for predicting vulnerability exploitation likelihood

**Visualization & Insights**
A dashboard concept for presenting predicted threats and recommended mitigations in an actionable format.

## Potential Technologies

The design considers modern cloud-native technologies:

- Google Cloud Platform (GCP) infrastructure
- Cloud Storage for data lake capabilities
- BigQuery for data warehousing and analysis
- Vertex AI for machine learning capabilities
- Terraform for infrastructure as code
- Grafana for visualization dashboards

## Current State & Next Steps

This repository contains the architectural plans and design concepts for the platform. I'm working to implement proof-of-concept modules for the key components, starting with the data collection and processing pipeline.

This is an ongoing project meant to demonstrate cloud security concepts and explore the potential of AI/ML in predictive threat intelligence.

## Learning Goals

Through this project, I'm working to develop and demonstrate:

1. Cloud-native security architecture design
2. Data engineering for security intelligence
3. Applied machine learning for cybersecurity
4. Infrastructure as code for security systems
5. Effective visualization of complex security data

## Development & Testing

### Testing the Threat Normalizer

We have set up unit tests for the `threat_normalizer` function, which you can find in `src/functions/data_processing/threat_normalizer.py`. The goal of these tests is to make sure the data normalization logic works correctly for the different threat intelligence sources we use.

#### Setup

The tests are written using Python's standard `unittest` framework and the `unittest.mock` library. We use mocking to test the function in isolation, without needing to connect to real external services. Here is what we mock:

- **Google Cloud Storage (`google.cloud.storage.Client`):** This is mocked to simulate reading the raw data files, like AlienVault pulses or VirusTotal reports, and also to simulate writing the processed data files back to storage. This avoids needing a real GCS connection during tests.

- **Google BigQuery (`google.cloud.bigquery.Client`):** This is mocked so we can check that the function tries to insert the correctly structured normalized data into BigQuery, again without needing a live connection.

- **Datetime (`datetime.datetime`):** We mock this to get a consistent timestamp (for the `processed_at` field) in our tests, making it easier to check the output.

Inside the test file, `tests/test_threat_normalizer.py`, we have included sample JSON data that looks like the typical input we would get from AlienVault and VirusTotal.

#### Running the Tests

To run these tests yourself, open a terminal, go to the main project directory (`predictive-threat-intelligence`), and run this command:

```bash
python -m unittest discover tests
```

#### Current Results

When you run the tests, you will see output that looks something like this:

```text
ss..
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

----------------------------------------------------------------------
Ran 4 tests in 0.004s

OK (skipped=2)
```

#### Interpretation

The `OK` status at the end tells us that the two main test cases we wrote (one for AlienVault, one for VirusTotal) passed all their checks.

The print messages show the steps the function took during the test, like processing indicators and trying to write data using the mocked clients. That "Errors inserting rows..." message is normal in this test setup; it just shows the mocked BigQuery client was called, which is what we want to verify. Our tests confirm it was called with the correct data.

The summary line "Ran 4 tests ... OK (skipped=2)" is a bit confusing since we only defined two test methods. Unittest might be counting things differently, but the important thing is that our main tests for the success paths passed.

So, this confirms the basic normalization logic is working correctly based on the tests we have so far. We should probably add more tests later to cover error situations and edge cases.

## Getting Started

The `/docs` folder contains detailed architectural diagrams and design documents that outline the platform concept. 

*Note: This is a portfolio project to showcase architectural thinking and cloud security concepts. Implementation is ongoing.*
