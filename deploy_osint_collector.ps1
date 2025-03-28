# PowerShell script to deploy OSINT Collector to Google Cloud
Write-Host "Deploying OSINT Collector to Google Cloud Functions..." -ForegroundColor Green

# Set your Google Cloud project ID here
$PROJECT_ID = "predictive-threat-intelligence"

# Set the region for deployment
$REGION = "us-central1"

# Set the function name
$FUNCTION_NAME = "osint-collector"

# Set the topic name for Cloud Scheduler
$TOPIC_NAME = "trigger-osint-collector"

# Set the scheduler job name
$SCHEDULER_NAME = "daily-osint-collection"

# Set the schedule (default: every day at 2:00 AM)
$SCHEDULE = "0 2 * * *"

Write-Host "Step 1: Deploying Cloud Function from src/functions/osint_collector..." -ForegroundColor Cyan
$deployCmd = "gcloud functions deploy $FUNCTION_NAME --gen2 --runtime=python39 --region=$REGION --source=src/functions/osint_collector --entry-point=collect_osint_data --trigger-topic=$TOPIC_NAME --memory=256MB --timeout=540s --set-env-vars=OTX_API_KEY=afe3c379e94165e6c8ccff2bd85a6ffc610bfed7ef7d60da1e37892324bd481c,GCS_RAW_BUCKET=mikedominic92-pti-raw-data"
Write-Host $deployCmd
Invoke-Expression $deployCmd

Write-Host "Step 2: Creating Cloud Scheduler job..." -ForegroundColor Cyan
$schedulerCmd = "gcloud scheduler jobs create pubsub $SCHEDULER_NAME --schedule='$SCHEDULE' --topic=$TOPIC_NAME --message-body='Run OSINT collection' --time-zone='America/New_York' --location=$REGION"
Write-Host $schedulerCmd
Invoke-Expression $schedulerCmd

Write-Host "Deployment complete!" -ForegroundColor Green
Write-Host "The OSINT collector will run automatically every day at 2:00 AM." -ForegroundColor Green
