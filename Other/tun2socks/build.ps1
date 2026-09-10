Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path '..\release' -Force | Out-Null

$source = Join-Path (Resolve-Path '..\..').Path 'tun2socks.exe'
if (-not (Test-Path -LiteralPath $source)) {
    throw "Local tun2socks 2.7 binary is missing: $source"
}

$expectedHash = '076B3C3D6A372BAE3F49F2B415A4105F70C30A3ED3CAAED7979390E649892559'
$actualHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
if (-not $actualHash.Equals($expectedHash, [StringComparison]::OrdinalIgnoreCase)) {
    throw "tun2socks 2.7 hash mismatch. Expected $expectedHash, got $actualHash"
}

Copy-Item -LiteralPath $source -Destination '..\release\tun2socks.exe' -Force
