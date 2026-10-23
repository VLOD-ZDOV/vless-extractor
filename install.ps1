$ErrorActionPreference = "Stop"

$Repo = if ($env:REPO) { $env:REPO } else { "VLOD-ZDOV/vless-extractor" }
$BinaryName = "vless-extract.exe"
$DownloadUrl = "https://github.com/$Repo/releases/latest/download/$BinaryName"
$InstallDir = "$env:LOCALAPPDATA\vless-extractor"

Write-Host "[*] Installing $BinaryName from $Repo..." -ForegroundColor Cyan

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$TargetPath = Join-Path $InstallDir $BinaryName
Write-Host "[*] Downloading $DownloadUrl..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TargetPath -UseBasicParsing

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "[*] Adding $InstallDir to User PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path += ";$InstallDir"
}

Write-Host "[+] Successfully installed $BinaryName to $TargetPath" -ForegroundColor Green
Write-Host "[+] You can now run 'vless-extract' from any terminal." -ForegroundColor Green
