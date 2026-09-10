Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path '..\release' -Force | Out-Null

$source = Join-Path (Resolve-Path '..\..').Path 'pcap2socks\pcap2socks.exe'
if (-not (Test-Path -LiteralPath $source)) {
    throw "Local pcap2socks binary is missing: $source"
}

$expectedHash = 'DE84F4A32C8C9D4888197345D52BA793E4BDF510614852E76F336F627E43DEF3'
$actualHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
if (-not $actualHash.Equals($expectedHash, [StringComparison]::OrdinalIgnoreCase)) {
    throw "pcap2socks v0.6.2 hash mismatch. Expected $expectedHash, got $actualHash"
}

Copy-Item -LiteralPath $source -Destination '..\release\pcap2socks.exe' -Force
