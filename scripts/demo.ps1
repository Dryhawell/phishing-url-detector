# Portföy demo scripti (Windows PowerShell)
# Kullanım:  .\scripts\demo.ps1

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host "== Phishing URL Detector demo ==" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Unit tests" -ForegroundColor Yellow
python -m pytest tests -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "[2/3] Batch sample analysis" -ForegroundColor Yellow
python main.py --batch samples/urls.txt --output reports/demo_batch.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "[3/3] Next manual steps" -ForegroundColor Yellow
Write-Host "  GUI : python main.py"
Write-Host "  API : python main.py --api"
Write-Host "  Ext : load browser-extension/ in chrome://extensions"
Write-Host "  Rel : https://github.com/Dryhawell/phishing-url-detector/releases/new?tag=v1.4.2"
Write-Host ""
Write-Host "Demo batch report: reports/demo_batch.json" -ForegroundColor Green
