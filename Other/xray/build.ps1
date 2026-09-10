Push-Location $PSScriptRoot
$ErrorActionPreference = 'Stop'

try {
    New-Item -ItemType Directory -Path '..\release' -Force | Out-Null

    # Update this version and all digests deliberately when updating the
    # audited Xray release.
    $xrayVersion = '26.3.27'
    $xrayArchiveUri = "https://github.com/XTLS/Xray-core/releases/download/v$xrayVersion/Xray-windows-64.zip"
    $expectedArchiveHash = 'd004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad'
    $expectedHashes = @{
        'xray.exe' = '15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1'
        'geoip.dat' = '744c97b74c52bae2ac8664fef6ac481d7765cb8432a0df54f0368a88b9b4a354'
        'geosite.dat' = 'adf92de0cfc70e458b399f04c5f912bf42d115ed7e37281b30e2f1c68605e4e9'
    }

    # Use an explicitly supplied release directory first, then the sibling
    # checkout. CI has neither, so download this exact audited release.
    $downloadDirectory = $null
    if (-not [string]::IsNullOrWhiteSpace($Env:NETCH_XRAY_RELEASE)) {
        $releasePath = [IO.Path]::GetFullPath($Env:NETCH_XRAY_RELEASE)
        if (-not (Test-Path -LiteralPath $releasePath -PathType Container)) {
            throw "NETCH_XRAY_RELEASE does not exist: $releasePath"
        }
    }
    else {
        $siblingReleasePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\xray-core\release'))
        if (Test-Path -LiteralPath $siblingReleasePath -PathType Container) {
            $releasePath = $siblingReleasePath
        }
        else {
            $downloadDirectory = Join-Path ([IO.Path]::GetTempPath()) "NetchX-Xray-$xrayVersion-$([Guid]::NewGuid().ToString('N'))"
            $archivePath = Join-Path $downloadDirectory 'Xray-windows-64.zip'
            New-Item -ItemType Directory -Path $downloadDirectory -Force | Out-Null

            Write-Host "Downloading Xray $xrayVersion for this build"
            Invoke-WebRequest -Uri $xrayArchiveUri -OutFile $archivePath -MaximumRedirection 5 -ErrorAction Stop

            $actualArchiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualArchiveHash -ne $expectedArchiveHash) {
                throw "Downloaded Xray archive did not match the pinned SHA-256: $xrayArchiveUri"
            }

            $releasePath = Join-Path $downloadDirectory 'release'
            Expand-Archive -LiteralPath $archivePath -DestinationPath $releasePath -Force
        }
    }

    foreach ($file in @('xray.exe', 'geoip.dat', 'geosite.dat')) {
        $source = Join-Path $releasePath $file
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Required Xray release file is missing: $source"
        }

        $actualHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHashes[$file]) {
            throw "Xray release file did not match the pinned SHA-256: $source"
        }

        Copy-Item -LiteralPath $source -Destination (Join-Path '..\release' $file) -Force
    }
}
finally {
    if ($null -ne $downloadDirectory -and (Test-Path -LiteralPath $downloadDirectory -PathType Container)) {
        Remove-Item -LiteralPath $downloadDirectory -Recurse -Force
    }

    Pop-Location
}
