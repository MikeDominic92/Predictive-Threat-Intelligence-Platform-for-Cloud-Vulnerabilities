# PowerShell script to deploy the Risk Prediction API to Google Cloud Functions

# Load environment variables from .env file
$envPath = Join-Path $PSScriptRoot ".env"
if (Test-Path $envPath) {
    Get-Content $envPath | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            # Strip quotes if present
            if ($value -match '^"(.*)"$' -or $value -match "^'(.*)'$") {
                $value = $matches[1]
            }
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
            Write-Host "Set environment variable: $name"
        }
    }
}

# Get required environment variables
$PROJECT_ID = [Environment]::GetEnvironmentVariable("PROJECT_ID", "Process")
$REGION = "us-central1" # Default region, modify as needed

# Set function name, source directory, and runtime
$FUNCTION_NAME = "predict-indicator-risk"
$SOURCE_DIR = ".\src\functions\risk_prediction"
$RUNTIME = "python311"
$GCS_BUCKET_NAME = [Environment]::GetEnvironmentVariable("GCS_BUCKET_NAME", "Process")

# Check if required variables are set
if (-not $PROJECT_ID) {
    Write-Error "PROJECT_ID is not set. Please set it in your .env file."
    exit 1
}

if (-not $GCS_BUCKET_NAME) {
    Write-Error "GCS_BUCKET_NAME is not set. Please set it in your .env file."
    exit 1
}

# Display deployment information
Write-Host ""
Write-Host "Deploying Risk Prediction API Cloud Function..."
Write-Host "Project ID: $PROJECT_ID"
Write-Host "Function Name: $FUNCTION_NAME"
Write-Host "Source Directory: $SOURCE_DIR"
Write-Host "Runtime: $RUNTIME"
Write-Host "Region: $REGION"
Write-Host ""

# Deploy the function
$deployCommand = "gcloud functions deploy $FUNCTION_NAME " + `
                 "--gen2 " + `
                 "--runtime=$RUNTIME " + `
                 "--region=$REGION " + `
                 "--source=$SOURCE_DIR " + `
                 "--entry-point=predict_indicator_risk " + `
                 "--trigger-http " + `
                 "--allow-unauthenticated " + `
                 "--timeout=180s " + `
                 "--memory=512Mi " + `
                 "--project=$PROJECT_ID " + `
                 "--set-env-vars=PROJECT_ID=$PROJECT_ID,GCS_BUCKET_NAME=$GCS_BUCKET_NAME"

Write-Host "Executing: $deployCommand"
Write-Host ""

Invoke-Expression $deployCommand

# Check if deployment was successful
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Deployment successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your API is now available. You can call it with:"
    Write-Host "curl -X POST https://$REGION-$PROJECT_ID.cloudfunctions.net/$FUNCTION_NAME -H 'Content-Type: application/json' -d '{\"indicator_type\":\"domain\",\"source\":\"alienvault\",\"value\":\"example.com\",\"tags\":[\"suspicious\"]}'"
    Write-Host ""
} else {
    Write-Host "Deployment failed!" -ForegroundColor Red
}
