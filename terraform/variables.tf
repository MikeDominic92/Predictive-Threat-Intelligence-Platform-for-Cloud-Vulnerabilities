variable "project_id" {
  description = "The GCP Project ID"
  type        = string
  default     = "predictive-threat-intelligence"
}

variable "region" {
  description = "The GCP region for deploying resources"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The GCP zone for deploying zonal resources"
  type        = string
  default     = "us-central1-a"
}

variable "storage_class" {
  description = "Storage class for GCS buckets"
  type        = string
  default     = "STANDARD"
}

variable "ml_engine_machine_type" {
  description = "Machine type for prediction engine"
  type        = string
  default     = "n1-standard-4"
}

variable "bq_dataset_location" {
  description = "BigQuery dataset location"
  type        = string
  default     = "US"
}

variable "collector_schedule" {
  description = "Cron schedule for data collection"
  type        = string
  default     = "0 */3 * * *"  # Every 3 hours
}
