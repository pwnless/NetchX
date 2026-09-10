Push-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)

$ErrorActionPreference = 'Stop'
.\clean.ps1
New-Item -ItemType Directory -Path '.\release' -Force | Out-Null

# v2ray-sn is a compatibility-only fallback for SSH and ShadowsocksR.
foreach ($name in @('aiodns', 'pcap2socks', 'tun2socks', 'xray', 'v2ray-sn', 'wintun')) {
    Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)
    Write-Host "Building $name"
    & ".\$name\build.ps1"
    if (-not $?) {
        Write-Host "Build $name failed"
        exit $lastExitCode
    }
}

Write-Host

Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)
Get-ChildItem -Path '.\release' -File | ForEach-Object {
    $name=$_.Name
    $hash=(Get-FileHash ".\release\$name" -Algorithm SHA256).Hash.ToLower()

    Write-Host "$hash $name"
}

Pop-Location
exit 0
