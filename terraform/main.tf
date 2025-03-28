terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.0"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Storage bucket for raw threat intelligence data
resource "google_storage_bucket" "threat_intel_raw" {
  name     = "${var.project_id}-threat-intel-raw"
  location = var.region
  uniform_bucket_level_access = true
  
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}

# BigQuery dataset for processed threat intelligence
resource "google_bigquery_dataset" "threat_intelligence" {
  dataset_id    = "threat_intelligence"
  friendly_name = "Threat Intelligence Dataset"
  description   = "Contains processed and analyzed threat intelligence data"
  location      = var.region

  access {
    role          = "OWNER"
    special_group = "projectOwners"
  }
}

# Pub/Sub topic for real-time threat intelligence updates
resource "google_pubsub_topic" "threat_intel_updates" {
  name = "threat-intel-updates"
}

# Cloud Function for data ingestion
resource "google_storage_bucket" "function_bucket" {
  name     = "${var.project_id}-functions"
  location = var.region
}

# Example data collector function
resource "google_cloudfunctions_function" "osint_collector" {
  name        = "osint-collector"
  description = "Collects threat intelligence from open source feeds"
  runtime     = "python310"

  available_memory_mb   = 256
  source_archive_bucket = google_storage_bucket.function_bucket.name
  source_archive_object = google_storage_bucket_object.function_source.name
  
  entry_point = "collect_osint"
  
  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.scheduler_topic.name
  }

  environment_variables = {
    PROJECT_ID = var.project_id
    RAW_BUCKET = google_storage_bucket.threat_intel_raw.name
  }
}

# Scheduler topic to trigger the collector
resource "google_pubsub_topic" "scheduler_topic" {
  name = "schedule-osint-collection"
}

# Cloud scheduler to trigger data collection every hour
resource "google_cloud_scheduler_job" "osint_collection_job" {
  name        = "hourly-osint-collection"
  description = "Triggers OSINT collection every hour"
  schedule    = "0 * * * *"

  pubsub_target {
    topic_name = google_pubsub_topic.scheduler_topic.id
    data       = base64encode("{\"sources\": [\"alienvault\", \"virustotal\"]}")
  }
}

# Placeholder for function source
resource "google_storage_bucket_object" "function_source" {
  name   = "function-source.zip"
  bucket = google_storage_bucket.function_bucket.name
  source = "../src/functions/data_ingestion/function_source.zip"
}
