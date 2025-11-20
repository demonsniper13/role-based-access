# PowerShell script to set up the virtual environment
Write-Host "Creating virtual environment..." -ForegroundColor Green
python -m venv venv

Write-Host "`nActivating virtual environment..." -ForegroundColor Green
& .\venv\Scripts\Activate.ps1

Write-Host "`nInstalling dependencies..." -ForegroundColor Green
pip install -r requirements.txt

Write-Host "`nSetup complete!" -ForegroundColor Green
Write-Host "`nTo activate the virtual environment in the future, run:" -ForegroundColor Yellow
Write-Host "  .\venv\Scripts\Activate.ps1" -ForegroundColor Cyan
Write-Host "`nTo run the application, use:" -ForegroundColor Yellow
Write-Host "  python app.py" -ForegroundColor Cyan

