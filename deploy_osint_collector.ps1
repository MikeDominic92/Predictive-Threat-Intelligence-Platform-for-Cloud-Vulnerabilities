# PowerShell script to deploy OSINT Collector to Google Cloud
Write-Host "Deploying OSINT Collector to Google Cloud Functions..." -ForegroundColor Green

# ===============================================
# LOAD ALL CONFIGURATION VALUES FROM .ENV FILE
# ===============================================

# Load variables from .env file
Write-Host "Loading environment variables from .env file..." -ForegroundColor Cyan
if (Test-Path ".env") {
    Get-Content ".env" | ForEach-Object {
        if ($_ -match '^([^#][^=]*)=(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            # Set as environment variable
            [System.Environment]::SetEnvironmentVariable($key, $value)
            Write-Host "Loaded: $key" -ForegroundColor DarkGray
        }
    }
    Write-Host "Environment variables loaded successfully" -ForegroundColor Green
} else {
    Write-Warning ".env file not found. Using existing environment variables."
}

# 1. PROJECT CONFIGURATION
# -----------------------------------------------
# Get Google Cloud project ID from environment variables
$PROJECT_ID = $env:PROJECT_ID

# If not set in environment, use hardcoded default
if (-not $PROJECT_ID) {
    $PROJECT_ID = "predictive-threat-intelligence"
    Write-Host "PROJECT_ID not found in environment, using default: $PROJECT_ID" -ForegroundColor Yellow
}

# Explicitly set the project in gcloud config
Write-Host "Setting active Google Cloud project to: $PROJECT_ID" -ForegroundColor Cyan
gcloud config set project $PROJECT_ID --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to set Google Cloud project. Please check your permissions."
    exit 1
}

# Verify current project
$CURRENT_PROJECT = gcloud config get-value project
Write-Host "Verified active project: $CURRENT_PROJECT" -ForegroundColor Green

# 2. DEPLOYMENT REGION
# -----------------------------------------------
$REGION = "us-central1"
Write-Host "Using region: $REGION" -ForegroundColor Cyan

# Set the function name
$FUNCTION_NAME = "osint-collector"

# Set the topic name for Cloud Scheduler
$TOPIC_NAME = "trigger-osint-collector"

# Set the scheduler job name
$SCHEDULER_NAME = "daily-osint-collection"

# Set the schedule (default: every day at 2:00 AM)
$SCHEDULE = "0 2 * * *"

Write-Host "Step 1: Deploying Cloud Function from src/functions/osint_collector..." -ForegroundColor Cyan

# Load API keys from environment variables
$ALIENVAULT_API_KEY = $env:ALIENVAULT_API_KEY
if (-not $ALIENVAULT_API_KEY -or $ALIENVAULT_API_KEY -eq "your-alienvault-api-key") {
    Write-Warning "ALIENVAULT_API_KEY environment variable is not set or contains a placeholder value!"
    $confirmation = Read-Host "Do you want to continue anyway? (y/n)"
    if ($confirmation -ne 'y') {
        exit 1
    }
}

$VIRUSTOTAL_API_KEY = $env:VIRUSTOTAL_API_KEY
if (-not $VIRUSTOTAL_API_KEY -or $VIRUSTOTAL_API_KEY -eq "your-virustotal-api-key") {
    Write-Warning "VIRUSTOTAL_API_KEY environment variable is not set or contains a placeholder value!"
    $confirmation = Read-Host "Do you want to continue anyway? (y/n)"
    if ($confirmation -ne 'y') {
        exit 1
    }
}

$BUCKET_NAME = $env:GCS_BUCKET_NAME
if (-not $BUCKET_NAME) {
    Write-Error "GCS_BUCKET_NAME environment variable is not set! Please set it before running this script."
    exit 1
}

# 4. CREATE PUB/SUB TOPIC (IF IT DOES NOT EXIST)
# -----------------------------------------------
Write-Host "Checking/Creating Pub/Sub topic: $TOPIC_NAME..." -ForegroundColor Cyan

# Check if topic exists by trying to describe it
gcloud pubsub topics describe $TOPIC_NAME --project=$CURRENT_PROJECT --quiet | Out-Null

if ($LASTEXITCODE -ne 0) { # If describe failed, topic likely doesn't exist
    Write-Host "Pub/Sub topic '$TOPIC_NAME' not found. Creating it..." -ForegroundColor Yellow
    gcloud pubsub topics create $TOPIC_NAME --project=$CURRENT_PROJECT
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create Pub/Sub topic '$TOPIC_NAME'. Please check permissions."
        exit 1
    }
    Write-Host "Pub/Sub topic '$TOPIC_NAME' created successfully." -ForegroundColor Green
} else {
    Write-Host "Pub/Sub topic '$TOPIC_NAME' already exists." -ForegroundColor Green
}

# 5. CHECK API KEYS & BUCKET
# -----------------------------------------------
Write-Host "Checking API Keys and GCS Bucket Name..." -ForegroundColor Cyan

# 5. EXECUTE DEPLOYMENT COMMANDS
# -----------------------------------------------

# Construct the Cloud Function deployment command with explicit project
Write-Host "Building deployment command with verified parameters..." -ForegroundColor Cyan

# Note: We'll build the command explicitly and execute it with proper error checking
# Step 1: Create a Pub/Sub topic if it doesn't exist already
Write-Host "Creating/verifying Pub/Sub topic: $TOPIC_NAME..." -ForegroundColor Cyan
gcloud pubsub topics create $TOPIC_NAME --project=$CURRENT_PROJECT --quiet 2>$null
# Even if it fails because it already exists, that's okay

# Build the deployment command with the correct trigger syntax
$deployCmd = "gcloud functions deploy $FUNCTION_NAME --gen2 --runtime=python39 --region=$REGION --project=$CURRENT_PROJECT --source=src/functions/osint_collector --entry-point=collect_osint_data --trigger-topic=$TOPIC_NAME --memory=256MB --timeout=540s --set-env-vars=ALIENVAULT_API_KEY=$ALIENVAULT_API_KEY,VIRUSTOTAL_API_KEY=$VIRUSTOTAL_API_KEY,GCS_BUCKET_NAME=$BUCKET_NAME,PROJECT_ID=$CURRENT_PROJECT"

# Execute the command
Write-Host "EXECUTING Cloud Function deployment..." -ForegroundColor Yellow
Write-Host $deployCmd -ForegroundColor DarkGray

# Run the command
Invoke-Expression $deployCmd

# Check exit code
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cloud Function deployment failed. Please check the error messages above."
    Write-Warning "You may need different permissions on this Google Cloud project."
    exit 1
}

Write-Host "Cloud Function '$FUNCTION_NAME' deployed successfully!" -ForegroundColor Green

# Create Cloud Scheduler job with explicit project
Write-Host "Step 2: Creating Cloud Scheduler job..." -ForegroundColor Cyan

# Build simple command string for scheduler
$schedulerCmd = "gcloud scheduler jobs create pubsub $SCHEDULER_NAME --schedule='$SCHEDULE' --topic=$TOPIC_NAME --message-body='Run OSINT collection' --time-zone='America/New_York' --location=$REGION --project=$CURRENT_PROJECT"

Write-Host "EXECUTING Cloud Scheduler job creation..." -ForegroundColor Yellow
Write-Host $schedulerCmd -ForegroundColor DarkGray

# Run the command
Invoke-Expression $schedulerCmd

# Check exit code
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cloud Scheduler job creation failed. Please check the error messages above."
    Write-Warning "You may need different permissions on this Google Cloud project."
    exit 1
}

Write-Host "Cloud Scheduler job '$SCHEDULER_NAME' created successfully!" -ForegroundColor Green

Write-Host "Deployment complete!" -ForegroundColor Green
Write-Host "The OSINT collector will run automatically every day at 2:00 AM." -ForegroundColor Green
