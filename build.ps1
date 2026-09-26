param (
	[Parameter()]
	[ValidateSet('Debug', 'Release')]
	[string]
	$Configuration = 'Release',

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]
	$OutputPath = 'release',

	[Parameter()]
	[bool]
	$SelfContained = $True,

	[Parameter()]
	[bool]
	$PublishSingleFile = $True,

	[Parameter()]
	[bool]
	$PublishReadyToRun = $False
)

$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)

$repositoryRoot = (Get-Location).Path
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$msbuild = if (Test-Path -LiteralPath $vswhere) {
    $vsInstallPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
    $candidate = Join-Path $vsInstallPath 'MSBuild\Current\Bin\MSBuild.exe'
    if (Test-Path -LiteralPath $candidate) { $candidate }
}
if (-not $msbuild) {
    $msbuild = (Get-Command msbuild.exe -ErrorAction Stop).Source
}

$releaseRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'release'))
$outputFullPath = [IO.Path]::GetFullPath($OutputPath, $repositoryRoot)
if (-not $outputFullPath.Equals($releaseRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The complete package is always built under '$releaseRoot'. The legacy build/ output directory is no longer supported."
}
$outputFullPath = $releaseRoot

if (Test-Path -LiteralPath $outputFullPath) {
    Remove-Item -LiteralPath $outputFullPath -Recurse -Force
}
New-Item -ItemType Directory -Path $outputFullPath | Out-Null

Push-Location $outputFullPath
New-Item -ItemType Directory -Name 'bin'  | Out-Null
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'Storage\i18n') -Destination '.' -Recurse -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'Storage\mode') -Destination '.' -Recurse -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'Storage\stun.txt') -Destination 'bin' -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'Storage\nfdriver.sys') -Destination 'bin' -Force
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'Storage\aiodns.conf') -Destination 'bin' -Force
$localCountryDatabase = Join-Path $repositoryRoot 'Country.mmdb'
if (Test-Path -LiteralPath $localCountryDatabase) {
    Copy-Item -LiteralPath $localCountryDatabase -Destination 'bin\GeoLite2-Country.mmdb' -Force
}
else {
    $geoRelease = Invoke-RestMethod -Uri 'https://api.github.com/repos/Loyalsoldier/geoip/releases/latest' -ErrorAction Stop
    $countryAsset = @($geoRelease.assets | Where-Object { $_.name -eq 'Country.mmdb' })[0]
    if ($null -eq $countryAsset -or [string]::IsNullOrWhiteSpace($countryAsset.browser_download_url)) {
        throw 'The latest Loyalsoldier/geoip release does not contain Country.mmdb.'
    }
    Invoke-WebRequest -Uri $countryAsset.browser_download_url -OutFile 'bin\GeoLite2-Country.mmdb' -ConnectionTimeoutSeconds 45 -OperationTimeoutSeconds 600 -ErrorAction Stop
    $downloadedCountryDatabase = Get-Item -LiteralPath 'bin\GeoLite2-Country.mmdb'
    $expectedDigest = $countryAsset.digest -replace '^sha256:', ''
    $actualDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $downloadedCountryDatabase.FullName).Hash
    if ($downloadedCountryDatabase.Length -ne $countryAsset.size -or
        (-not [string]::IsNullOrWhiteSpace($expectedDigest) -and -not $actualDigest.Equals($expectedDigest, [StringComparison]::OrdinalIgnoreCase))) {
        throw 'Country.mmdb download did not match the latest release metadata.'
    }
}
#cp -Recurse -Force '..\Storage\GeoLite2-Country.mmdb' 'bin'  | Out-Null
Copy-Item -LiteralPath (Join-Path $repositoryRoot 'Storage\README.md') -Destination 'bin' -Force
Pop-Location

& .\Other\build.ps1
if ( -Not $? ) {
	exit $lastExitCode
}
cp -Force '.\Other\release\*.bin' "$outputFullPath\bin"
cp -Force '.\Other\release\*.dll' "$outputFullPath\bin"
cp -Force '.\Other\release\*.exe' "$outputFullPath\bin"
cp -Force '.\Other\release\*.dat' "$outputFullPath\bin"
cp -Force '.\Other\release\*.LICENSE' "$outputFullPath\bin"

Write-Host
Write-Host 'Building NetchX'

dotnet publish `
	-c $Configuration `
	-r 'win-x64' `
	-p:Platform='x64' `
	-p:SelfContained=$SelfContained `
	-p:PublishTrimmed=$PublishReadyToRun `
	-p:PublishSingleFile=$PublishSingleFile `
	-p:PublishReadyToRun=$PublishReadyToRun `
	-p:PublishReadyToRunShowWarnings=$PublishReadyToRun `
	-p:IncludeNativeLibrariesForSelfExtract=$SelfContained `
	-o ".\NetchX\bin\$Configuration" `
	'.\NetchX\NetchX.csproj'
if ( -Not $? ) { exit $lastExitCode }
cp -Force ".\NetchX\bin\$Configuration\NetchX.exe" $outputFullPath

Write-Host
Write-Host 'Building Redirector'

& $msbuild `
	-property:Configuration=$Configuration `
	-property:Platform=x64 `
	'.\Redirector\Redirector.vcxproj'
if ( -Not $? ) { exit $lastExitCode }
cp -Force ".\Redirector\bin\$Configuration\nfapi.dll"      "$outputFullPath\bin"
cp -Force ".\Redirector\bin\$Configuration\Redirector.bin" "$outputFullPath\bin"

Write-Host
Write-Host 'Building RouteHelper'

& $msbuild `
	-property:Configuration=$Configuration `
	-property:Platform=x64 `
	'.\RouteHelper\RouteHelper.vcxproj'
if ( -Not $? ) { exit $lastExitCode }
cp -Force ".\RouteHelper\bin\$Configuration\RouteHelper.bin" "$outputFullPath\bin"

$requiredFiles = @(
    'NetchX.exe',
    'bin\Redirector.bin',
    'bin\RouteHelper.bin',
    'bin\nfapi.dll',
    'bin\nfdriver.sys',
    'bin\aiodns.bin',
    'bin\aiodns.conf',
    'bin\pcap2socks.exe',
    'bin\tun2socks.exe',
    'bin\xray.exe',
    'bin\sing-box.exe',
    'bin\libcronet.dll',
    'bin\sing-box.LICENSE',
    'bin\geoip.dat',
    'bin\geosite.dat',
    'bin\wintun.dll',
    'bin\GeoLite2-Country.mmdb'
)
$missingFiles = @($requiredFiles | Where-Object { -not (Test-Path -LiteralPath (Join-Path $outputFullPath $_)) })
if ($missingFiles.Count -gt 0) {
    throw "Build output is incomplete. Missing: $($missingFiles -join ', ')"
}

if ( $Configuration.Equals('Release') ) {
    Remove-Item -Path (Join-Path $outputFullPath '*.pdb'), (Join-Path $outputFullPath '*.xml') -Force -ErrorAction SilentlyContinue
}

function Find-SevenZip {
    foreach ($name in @('7z.exe', '7z', '7za.exe', '7za')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -ne $command) { return $command.Source }
    }
    foreach ($candidate in @('C:\Program Files\7-Zip\7z.exe', 'C:\Program Files (x86)\7-Zip\7z.exe')) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

$projectText = Get-Content -LiteralPath (Join-Path $repositoryRoot 'NetchX\NetchX.csproj') -Raw
$versionMatch = [regex]::Match($projectText, '<Version>(?<value>[^<]+)</Version>')
if (-not $versionMatch.Success) { throw 'Could not read the package version from NetchX/NetchX.csproj.' }
$archiveBaseName = "NetchX-$($versionMatch.Groups['value'].Value)-win-x64"
if ($Configuration -ne 'Release') { $archiveBaseName = "$archiveBaseName-debug" }
$sevenZipArchive = Join-Path $outputFullPath "$archiveBaseName.7z"
$zipArchive = Join-Path $outputFullPath "$archiveBaseName.zip"
Remove-Item -LiteralPath $sevenZipArchive, $zipArchive -Force -ErrorAction SilentlyContinue

$packageTemporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "NetchX-package-$([Guid]::NewGuid().ToString('N'))"
$packagePayloadRoot = Join-Path $packageTemporaryRoot 'NetchX'
$packageArchive = $null
try {
    New-Item -ItemType Directory -Path $packagePayloadRoot -Force | Out-Null
    Get-ChildItem -LiteralPath $outputFullPath -Force | Where-Object {
        $_.FullName -ne $sevenZipArchive -and $_.FullName -ne $zipArchive
    } | Copy-Item -Destination $packagePayloadRoot -Recurse -Force

    $sevenZip = Find-SevenZip
    if ($sevenZip) {
        try {
            Push-Location $packageTemporaryRoot
            try {
                & $sevenZip 'a' '-t7z' $sevenZipArchive 'NetchX' | Out-Host
                if ($LASTEXITCODE -ne 0) { throw "7-Zip create failed with exit code $LASTEXITCODE." }
                & $sevenZip 't' $sevenZipArchive | Out-Host
                if ($LASTEXITCODE -ne 0) { throw "7-Zip verification failed with exit code $LASTEXITCODE." }
                $archiveListing = (& $sevenZip 'l' '-slt' $sevenZipArchive) -join "`n"
                if ($archiveListing -notmatch '(?m)^Path = NetchX[\\/]NetchX\.exe$') {
                    throw '7-Zip package does not contain NetchX/NetchX.exe.'
                }
            }
            finally {
                Pop-Location
            }
            $packageArchive = $sevenZipArchive
        }
        catch {
            Write-Warning "7-Zip packaging failed; falling back to ZIP. $($_.Exception.Message)"
            Remove-Item -LiteralPath $sevenZipArchive -Force -ErrorAction SilentlyContinue
        }
    }

    if ($null -eq $packageArchive) {
        Compress-Archive -LiteralPath $packagePayloadRoot -DestinationPath $zipArchive -CompressionLevel Optimal -ErrorAction Stop
        $zip = [IO.Compression.ZipFile]::OpenRead($zipArchive)
        try {
            if (-not ($zip.Entries.FullName -contains 'NetchX/NetchX.exe')) { throw 'ZIP package does not contain NetchX/NetchX.exe.' }
        }
        finally { $zip.Dispose() }
        $packageArchive = $zipArchive
    }
}
finally {
    Remove-Item -LiteralPath $packageTemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$packageHash = (Get-FileHash -LiteralPath $packageArchive -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host
Write-Host "Release layout: $outputFullPath"
Write-Host "Release archive: $packageArchive"
Write-Host "Release archive SHA-256: $packageHash"

Pop-Location
exit 0
