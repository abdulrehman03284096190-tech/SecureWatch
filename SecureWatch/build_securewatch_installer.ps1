$ErrorActionPreference = "Stop"
$appRoot = $PSScriptRoot
$workspaceRoot = Split-Path -Parent $appRoot
$payloadRoot = Join-Path $appRoot "dist\SecureWatch"
$appExe = Join-Path $payloadRoot "SecureWatch.exe"
$internalDirectory = Join-Path $payloadRoot "_internal"
$installerScript = Join-Path $appRoot "SecureWatch.iss"
$outputDirectory = Join-Path $workspaceRoot "Output"
$installerPath = Join-Path $outputDirectory "SecureWatch-Setup.exe"

foreach ($requiredPath in @($appExe, $internalDirectory, $installerScript)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required installer input is missing: $requiredPath"
    }
}
if (-not (Get-ChildItem -LiteralPath $internalDirectory -Force | Select-Object -First 1)) {
    throw "The bundled runtime directory is empty: $internalDirectory"
}

Write-Host "Application payload: $payloadRoot"
Write-Host "Searching for Inno Setup 6 compiler..."
$compiler = Get-ChildItem -LiteralPath $workspaceRoot -Filter "ISCC.exe" -File -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $compiler) {
    $standardCompilerPaths = @(
        (Join-Path ([Environment]::GetFolderPath("ProgramFiles")) "Inno Setup 6\ISCC.exe"),
        (Join-Path ([Environment]::GetFolderPath("ProgramFilesX86")) "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
    )
    $compilerPath = $standardCompilerPaths |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Select-Object -First 1
} else {
    $compilerPath = $compiler.FullName
}
if (-not $compilerPath) {
    throw "Inno Setup 6 ISCC.exe was not found under $workspaceRoot or in standard install locations."
}

New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
Write-Host "Compiler: $compilerPath"
Write-Host "Compiling installer..."
Push-Location $appRoot
try {
    & $compilerPath "/O$outputDirectory" $installerScript
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup compilation failed with exit code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
    throw "Compiler reported success but the installer was not created: $installerPath"
}
if ((Get-Item -LiteralPath $installerPath).Length -le 0) {
    throw "The generated installer is empty: $installerPath"
}

Write-Host "Installer created successfully: $installerPath"