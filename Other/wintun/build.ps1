Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path '..\release' -Force | Out-Null

$source = Join-Path (Resolve-Path '..\..').Path 'wintun\bin\amd64\wintun.dll'
if (-not (Test-Path -LiteralPath $source)) {
    throw "Local Wintun x64 binary is missing: $source"
}

$version = [Diagnostics.FileVersionInfo]::GetVersionInfo($source).FileVersion
if ($version -notmatch '^0\.14\.1') {
    throw "Expected Wintun 0.14.1, found '$version' at $source"
}

$expectedHash = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'
$actualHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
if (-not $actualHash.Equals($expectedHash, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Wintun 0.14.1 hash mismatch. Expected $expectedHash, got $actualHash"
}

Copy-Item -LiteralPath $source -Destination '..\release\wintun.dll' -Force
