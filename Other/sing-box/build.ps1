Push-Location $PSScriptRoot
$ErrorActionPreference = 'Stop'

try {
    New-Item -ItemType Directory -Path '..\release' -Force | Out-Null

    # Update the version, revision, archive hash, and asset hashes together.
    $singBoxVersion = '1.14.2'
    $singBoxRevision = 'af6e64c3b69e6132ebaee0e1a3d24e93903f6709'
    $archiveUri = "https://github.com/SagerNet/sing-box/releases/download/v$singBoxVersion/sing-box-$singBoxVersion-windows-amd64.zip"
    $expectedArchiveHash = 'c2d8bfff918755808781dfdeeb8581b6c91eb3a243d9a7b55483cfc0c0684d32'
    $expectedHashes = @{
        'sing-box.exe' = '7bbef1dea9189ee12799ae834ea4b4658355da25c47a21ad8804904c0ccd9410'
        'libcronet.dll' = '3217c6260fbca5f16072e0b79735742f40109a63bb0ff88fd6b96dd6b54a2928'
    }

    function Test-SingBoxReleaseDirectory([string]$candidatePath) {
        if ([string]::IsNullOrWhiteSpace($candidatePath) -or -not (Test-Path -LiteralPath $candidatePath -PathType Container)) {
            return $false
        }
        foreach ($file in $expectedHashes.Keys) {
            $source = Join-Path $candidatePath $file
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                return $false
            }
            $actualHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualHash -ne $expectedHashes[$file]) {
                return $false
            }
        }
        return $true
    }

    $downloadDirectory = $null
    if (-not [string]::IsNullOrWhiteSpace($Env:NETCHX_SING_BOX_RELEASE)) {
        $releasePath = [IO.Path]::GetFullPath($Env:NETCHX_SING_BOX_RELEASE)
        if (-not (Test-SingBoxReleaseDirectory $releasePath)) {
            throw "NETCHX_SING_BOX_RELEASE is missing or does not match the pinned sing-box $singBoxVersion assets: $releasePath"
        }
    }
    elseif (Test-SingBoxReleaseDirectory $PSScriptRoot) {
        $releasePath = [IO.Path]::GetFullPath($PSScriptRoot)
        Write-Host "Using locally cached sing-box $singBoxVersion ($singBoxRevision)"
    }
    else {
        $downloadDirectory = Join-Path ([IO.Path]::GetTempPath()) "NetchX-sing-box-$singBoxVersion-$([Guid]::NewGuid().ToString('N'))"
        $archivePath = Join-Path $downloadDirectory "sing-box-$singBoxVersion-windows-amd64.zip"
        New-Item -ItemType Directory -Path $downloadDirectory -Force | Out-Null

        Write-Host "Downloading sing-box $singBoxVersion for this build"
        Invoke-WebRequest -Uri $archiveUri -OutFile $archivePath -MaximumRedirection 5 -ErrorAction Stop
        $actualArchiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualArchiveHash -ne $expectedArchiveHash) {
            throw "Downloaded sing-box archive did not match the pinned SHA-256: $archiveUri"
        }

        $extractPath = Join-Path $downloadDirectory 'release'
        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force
        $releasePath = Get-ChildItem -LiteralPath $extractPath -Directory | Select-Object -First 1 -ExpandProperty FullName
        if (-not (Test-SingBoxReleaseDirectory $releasePath)) {
            throw "Downloaded sing-box release files did not match the pinned $singBoxVersion asset hashes."
        }
    }

    foreach ($file in $expectedHashes.Keys) {
        Copy-Item -LiteralPath (Join-Path $releasePath $file) -Destination (Join-Path '..\release' $file) -Force
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LICENSE') -Destination '..\release\sing-box.LICENSE' -Force
}
finally {
    if ($null -ne $downloadDirectory -and (Test-Path -LiteralPath $downloadDirectory -PathType Container)) {
        Remove-Item -LiteralPath $downloadDirectory -Recurse -Force
    }
    Pop-Location
}
