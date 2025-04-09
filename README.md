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

This layer collects data from various threat intelligence sources, including open-source feeds and cloud provider security services.

**Implementation:** The data collection is handled by the `osint_collector` Google Cloud Function (`src/functions/osint_collector`), which gathers:
  - Pulses from AlienVault OTX
  - IP Address reports from VirusTotal
  - Security Command Center findings from Google Cloud
  - Asset Inventory data from Google Cloud

Data is saved in JSON format to Google Cloud Storage with source-specific prefixes (`raw/alienvault/`, `raw/virustotal/`, `raw/scc/`, and `raw/asset/`).

### Data Processing Pipeline

A cloud-native pipeline normalizes and enriches the raw intelligence data, preparing it for analysis.

**Implementation:** The data processing pipeline is implemented in `src/functions/data_processing/` and includes:

- **Threat Normalizer** (`threat_normalizer.py`): A Cloud Function that processes incoming raw data from GCS, normalizes it through source-specific normalizers, and writes the results to BigQuery.

- **Source-Specific Normalizers**:
  - `normalizers/alienvault.py`: Normalizes AlienVault OTX pulse data
  - `normalizers/virustotal.py`: Normalizes VirusTotal IP reports
  - `normalizers/gcp_scc.py`: Normalizes Google Cloud Security Command Center findings
  - `normalizers/gcp_asset.py`: Normalizes Google Cloud Asset Inventory data

- **Common Schema**: All normalizers convert their source data to a common schema with fields like `indicator_type`, `indicator_value`, `confidence_score`, `severity`, etc.

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

This repository contains the architectural plans, design concepts, and working components for the platform. I've implemented several key modules, and I'm continuing to build out the functionality.

**Updates:**

1. **Data Collection:** The `osint_collector` Google Cloud Function for collecting data from AlienVault OTX, VirusTotal (IP reports), Google Cloud Security Command Center findings, and Google Cloud Asset Inventory has been implemented. Raw data is saved to Google Cloud Storage.

2. **Data Normalization:** A complete data normalization pipeline processes the raw threat data from all sources into a standardized format and stores it in BigQuery for analysis. Source-specific normalizers handle the unique aspects of each data source while ensuring consistent output format.

3. **ML Risk Prediction Model:** I've implemented a machine learning pipeline that:
   - Loads normalized threat data from BigQuery
   - Creates a target variable based on threat tags
   - Preprocesses features using one-hot encoding
   - Trains a RandomForest classifier to predict threat risk levels
   - Saves the trained model and preprocessor to Google Cloud Storage
   - Makes predictions on new threat indicators

4. **Risk Correlation Engine:** I've implemented a dedicated risk correlation engine that:
   - Correlates GCP Security Command Center findings with Asset Inventory data
   - Calculates risk scores based on finding severity and asset characteristics
   - Generates tailored mitigation recommendations
   - Stores correlation results in BigQuery for further analysis
   - Runs as a Cloud Function for automated and regular risk assessment

5. **Risk Prediction API:** I've added an API layer that exposes the ML model through HTTP requests. This feels like a critical component for a real-world tool - being able to integrate threat predictions with other security systems. The API is built to deploy as a Cloud Function but can run locally for testing too.

I was especially excited to complete the ML component as it's the heart of what makes this platform predictive rather than just reactive.

This is an ongoing project meant to demonstrate cloud security concepts and explore the potential of AI/ML in predictive threat intelligence.

## Learning Goals

Through this project, I'm working to develop and demonstrate:

1. Cloud-native security architecture design
2. Data engineering for security intelligence
3. Applying machine learning to cybersecurity problems
4. Infrastructure as code for security systems
5. Effective visualization of complex security data

## System Architecture

The platform consists of several key components that work together to create a complete threat intelligence pipeline:

### 1. OSINT Data Collection
The `osint_collector` Cloud Function automatically collects threat data from:
- **AlienVault OTX API**: For pulse data about emerging threats
- **VirusTotal API**: For detailed information about suspicious IPs, domains, and files
- **Google Cloud Security Command Center**: For findings related to security risks in your GCP environment
- **Google Cloud Asset Inventory**: For details about cloud assets to correlate with security findings

Data is collected on a schedule and stored in Google Cloud Storage for processing.

### 2. Threat Data Normalization
The `threat_normalizer` Cloud Function:
- Triggered when new data arrives in Cloud Storage
- Processes and normalizes raw data from different sources into a consistent format
- Handles different schema structures from AlienVault, VirusTotal, GCP Security Command Center, and GCP Asset Inventory
- Writes normalized data to BigQuery for analysis

### 3. Risk Correlation Engine
The `risk_correlation` Cloud Function:
- Correlates security findings from GCP Security Command Center with asset inventory data
- Calculates risk scores based on finding severity and asset characteristics
- Generates tailored mitigation recommendations for each security finding
- Stores correlation results in BigQuery for further analysis and reporting

### 4. Machine Learning Components (Future)
- Time series analysis to identify threat patterns
- NLP processing for unstructured advisory data
- Vulnerability prediction models

## GCP Security Integration

The platform integrates directly with Google Cloud Platform security services to provide comprehensive threat detection and risk assessment for cloud environments.

### Security Command Center Integration

The platform leverages Google Cloud Security Command Center (SCC) to collect security findings across your entire GCP organization:

- **Comprehensive Coverage**: Collects findings from Security Health Analytics, Event Threat Detection, Container Threat Detection, and Web Security Scanner
- **Finding Enrichment**: Enhances SCC findings with additional context about affected resources
- **Historical Analysis**: Maintains a historical record of all findings for trend analysis
- **Organization-wide View**: Provides a holistic view of security posture across all projects in your GCP organization

### Asset Inventory Integration

The platform integrates with Google Cloud Asset Inventory to maintain an up-to-date inventory of all cloud resources:

- **Complete Resource Tracking**: Monitors compute instances, storage buckets, databases, IAM policies, and network resources
- **Resource Relationships**: Maps relationships between resources to understand potential attack paths
- **Configuration Monitoring**: Tracks configuration changes that could impact security posture
- **Critical Asset Tagging**: Identifies and tags business-critical assets for prioritized risk assessment

### Risk Correlation Process

The Risk Correlation Engine performs the following steps to assess risk in your GCP environment:

1. **Data Collection**: Retrieves the latest security findings from SCC and asset data from Asset Inventory
2. **Finding Correlation**: Maps security findings to affected assets and identifies related resources
3. **Risk Scoring**: Calculates a risk score based on finding severity, asset criticality, and potential impact
4. **Mitigation Recommendation**: Generates specific mitigation steps based on the finding type and affected resource
5. **Result Storage**: Stores correlation results in BigQuery for further analysis and reporting

This integration provides automated, continuous risk assessment of your GCP environment based on real-time security telemetry.

## Deployment Guide

### Prerequisites

1. **Google Cloud Platform Account**
   - Project with billing enabled
   - Required APIs: Cloud Functions, Cloud Storage, BigQuery, Cloud Scheduler

2. **API Keys**
   - AlienVault OTX API key ([Register here](https://otx.alienvault.com/))
   - VirusTotal API key ([Register here](https://www.virustotal.com/gui/join-us))

3. **Local Environment**
   - Python 3.9+
   - Google Cloud SDK installed and configured
   - Required Python packages: `pip install -r requirements.txt`

### Setup Steps

1. **Configure Environment**
   - Create a `.env` file in the project root with the following variables:

   ```bash
   PROJECT_ID=your-gcp-project-id
   DATASET_ID=threat_intelligence
   TABLE_ID=normalized_threats
   GCS_BUCKET_NAME=your-bucket-name
   ALIENVAULT_API_KEY=your-alienvault-api-key
   VIRUSTOTAL_API_KEY=your-virustotal-api-key
   GCP_ORGANIZATION_ID=your-gcp-organization-id
   ```

2. **Create Google Cloud Resources**

   ```bash
   # Create GCS bucket
   gsutil mb -l us-central1 gs://your-bucket-name
   
   # Create BigQuery dataset and tables
   bq mk --dataset threat_intelligence
   bq mk --table threat_intelligence.normalized_threats ./schema/bigquery_schema.json
   bq mk --table threat_intelligence.risk_correlations ./schema/risk_correlation_schema.json
   ```


3. **Deploy Cloud Functions**
   - Use the provided deployment script to deploy all components:

   ```bash
   # Deploy all cloud functions
   python deploy_functions.py
   ```

   - Or you can deploy individual components using the specific deployment scripts:

   ```bash
   # Deploy OSINT collector
   ./deploy_osint_collector.bat
   
   # Deploy threat normalizer
   ./deploy_threat_normalizer.bat
   
   # Deploy risk correlation engine
   ./deploy_risk_correlation.bat
   ```

### End-to-End Testing

Run the end-to-end test to verify the entire pipeline:

```bash
python -m src.tests.end_to_end_test
```

This test will:
1. Validate all environment variables
2. Test API connectivity
3. Collect sample data from threat intelligence sources
4. Upload to Cloud Storage
5. Process and normalize the data
6. Insert into BigQuery

#### Testing Individual Components

1. **Test OSINT Data Collection**

   ```bash
   curl -X POST https://<your-region>-<your-project-id>.cloudfunctions.net/osint_collector
   ```

2. **Test GCP Data Collection**
   This step is automatically executed as part of the OSINT collector but can be tested individually:

   ```bash
   curl -X POST https://<your-region>-<your-project-id>.cloudfunctions.net/osint_collector -d '{"sources": ["gcp_scc", "gcp_asset"]}'
   ```

3. **Test Risk Correlation Engine**

   ```bash
   curl -X POST https://<your-region>-<your-project-id>.cloudfunctions.net/risk_correlation
   ```

4. **Verify Data in BigQuery**

   ```sql
   -- Check normalized threats
   SELECT * FROM `<your-project-id>.<dataset_id>.normalized_threats` LIMIT 100;
   
   -- Check risk correlation results
   SELECT * FROM `<your-project-id>.<dataset_id>.risk_correlations` LIMIT 100;
   ```

## Usage Guide

### Data Collection

The OSINT collector runs daily at 2:00 AM (configurable in `deploy_osint_collector.bat`). To manually trigger a collection:

```bash
gcloud pubsub topics publish trigger-osint-collector --message="Run OSINT collection"
```

To manually trigger the risk correlation engine:

```bash
gcloud pubsub topics publish trigger-risk-correlation --message="Run risk correlation"
```

To manually trigger the GCP data collection:

```bash
gcloud pubsub topics publish trigger-gcp-collector --message="Run GCP collection"
```

### Viewing Collected Data

1. **Raw Data in Cloud Storage**
   - Navigate to your GCS bucket in the Google Cloud Console
   - Raw data is stored in the following directories:
     - `raw/alienvault/`: AlienVault OTX pulses
     - `raw/virustotal/`: VirusTotal IP reports
     - `raw/scc/`: Google Cloud Security Command Center findings
     - `raw/asset/`: Google Cloud Asset Inventory data

2. **Normalized Data in BigQuery**
   - Run queries against the normalized threats table
   - Example query:

   ```sql
   SELECT * FROM `your-project.threat_intelligence.normalized_threats`
   WHERE threat_type = 'malicious_ip'
   ORDER BY confidence_score DESC
   LIMIT 100
   ```

3. **Risk Correlation Results**
   - View correlation results in the risk_correlations table
   - Example query:

```sql
SELECT * FROM `your-project.threat_intelligence.risk_correlations`
ORDER BY risk_score DESC
LIMIT 100
```

### Monitoring

The platform includes Datadog monitoring integration for production environments. For setup instructions, see `docs/datadog_monitoring.md`.

## Development & Testing

### Local Testing
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

### Using the ML Risk Prediction

I've created a simple command-line tool for demonstrating the ML risk prediction capabilities. After setting up your environment:

```bash
# Predict risk for a specific indicator
python src/predict_indicator_risk.py --indicator-type domain --source alienvault --tags suspicious

# Try with different indicator types and sources
python src/predict_indicator_risk.py --indicator-type ip --source virustotal --tags malicious botnet
python src/predict_indicator_risk.py --indicator-type url --source alienvault --tags phishing
```

The model evaluates the indicator and returns a risk prediction (HIGH or LOW) along with a confidence score.

### Using the Risk Prediction API

If you want to integrate the risk predictions with other systems, I've built an API that makes this pretty straightforward:

#### Local Testing

To try it out locally:

```bash
# Start the API server locally
python local_api_server.py

# In another terminal, test with example requests
python test_api_client.py
```

The API accepts POST requests with JSON like this:

```json
{
  "indicator_type": "domain",
  "value": "suspicious-domain.com",
  "source": "alienvault",
  "tags": ["suspicious", "phishing"]
}
```

And returns prediction results with confidence scores and feature importance - pretty neat for understanding why the model made its decision.

### Training the ML Model

If you want to retrain the model with fresh data:

```bash
python src/train_risk_model.py
```

This will fetch the latest data from BigQuery, train a new model, and save it to GCS.

*Note: This is a portfolio project showcasing cloud security, data engineering, and ML concepts. While many components are fully functional, it's designed as a demonstration rather than a production-ready solution.*

## Deployment

Deployment uses Terraform Cloud for managing infrastructure and Google Cloud Build for deploying the Cloud Function code.

### OSINT Collector Deployment (`osint_collector`)

The `osint_collector` function is deployed as a Google Cloud Function (Gen 2).



- **Deployment Command:** Uses `gcloud functions deploy ...` (see command history or documentation for exact flags).
- **Trigger:** Pub/Sub topic (e.g., `osint-collection-trigger`).
- **Required APIs:** Cloud Functions, Cloud Build, Eventarc, Pub/Sub, Cloud Storage.
- **Required Environment Variables:** See the section below.


### Risk Prediction API Deployment (`predict-indicator-risk`)

I've made deploying the API pretty simple with a PowerShell script (`deploy_risk_prediction_api.ps1`).



- **How it works:** The API runs as a Google Cloud Function that loads the ML model and makes predictions on demand.
- **Trigger:** HTTP requests - so you can call it from anywhere.
- **Configuration:** I set it up with 512MB memory and a 180s timeout since model loading takes a bit of time.
- **Testing:** The script includes helpful output examples once deployment succeeds.


Once deployed, you can call it with a simple HTTP request:

```bash
curl -X POST https://{REGION}-{PROJECT_ID}.cloudfunctions.net/predict-indicator-risk \
  -H "Content-Type: application/json" \
  -d '{"indicator_type":"domain","source":"alienvault","value":"example.com","tags":["suspicious"]}'
```

I found that adding this API layer really makes the whole system feel more complete and usable in a real security workflow.

### Environment Variables

The following environment variables are required for the project components:


**`osint_collector` Function:**

- `ALIENVAULT_API_KEY`: Your AlienVault OTX API key.
- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key (optional).
- `GCS_BUCKET_NAME`: The name of the Google Cloud Storage bucket where raw and processed data will be stored.

**Data Processing & ML Pipeline:**
- `PROJECT_ID`: Your Google Cloud Project ID.
- `DATASET_ID`: Your BigQuery Dataset ID (e.g., `threat_intelligence`).
- `TABLE_ID`: Your BigQuery Table ID (e.g., `normalized_threats`).

**Important Security Note:** 
Never commit files containing actual API keys to version control. Use environment variables or secure secret management services to handle sensitive credentials.

### Project Structure

**OSINT Collection:**
- `src/functions/osint_collector/main.py`: Cloud Function entry point (`collect_osint_data`), fetches data from threat sources.
- `src/functions/osint_collector/requirements.txt`: Python dependencies for the collector.

**Data Processing:**
- `src/functions/data_processing/threat_normalizer.py`: Orchestrates data normalization from raw files to BigQuery.
- `src/functions/data_processing/utils.py`: Helper functions for GCS & BigQuery operations.
- `src/functions/data_processing/normalizers/`: Source-specific normalization logic.

**Machine Learning:**
- `src/ml_engine/`: Contains the ML pipeline components:
  - `config.py`: Configuration settings for the ML pipeline.
  - `feature_engineering.py`: Creates target variables and preprocessing features.
  - `predictor.py`: Trains models and makes predictions.
  - `utils.py`: Helper functions for ML operations.
- `src/train_risk_model.py`: Main script for training the risk prediction model.
- `src/predict_indicator_risk.py`: CLI tool for getting risk predictions on new indicators.

**Dependencies:**
- `requirements.txt`: Core Python dependencies including scikit-learn, pandas, matplotlib and GCP libraries.

## License

MIT
