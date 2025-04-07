@echo off
echo Deploying OSINT Collector to Google Cloud Functions...

REM Set your Google Cloud project ID here
set PROJECT_ID=predictive-threat-intelligence

REM Set the region for deployment
set REGION=us-central1

REM Set the function name
set FUNCTION_NAME=osint-collector

REM Set the topic name for Cloud Scheduler
set TOPIC_NAME=trigger-osint-collector

REM Set the scheduler job name
set SCHEDULER_NAME=daily-osint-collection

REM Set the schedule (default: every day at 2:00 AM)
set SCHEDULE="0 2 * * *"

echo Step 1: Deploying Cloud Function from src/functions/osint_collector...
gcloud functions deploy %FUNCTION_NAME% \
  --gen2 \
  --runtime=python39 \
  --region=%REGION% \
  --source=src/functions/osint_collector \
  --entry-point=collect_osint_data \
  --trigger-topic=%TOPIC_NAME% \
  --memory=256MB \
  --timeout=540s \
  --set-env-vars="OTX_API_KEY=afe3c379e94165e6c8ccff2bd85a6ffc610bfed7ef7d60da1e37892324bd481c,GCS_RAW_BUCKET=mikedominic92-pti-raw-data"

echo Step 2: Creating Cloud Scheduler job...
gcloud scheduler jobs create pubsub %SCHEDULER_NAME% \
  --schedule=%SCHEDULE% \
  --topic=%TOPIC_NAME% \
  --message-body="Run OSINT collection" \
  --time-zone="America/New_York" \
  --location=%REGION%

echo Deployment complete!
echo The OSINT collector will run automatically every day at 2:00 AM.
