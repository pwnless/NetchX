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

$outputFullPath = [IO.Path]::GetFullPath($OutputPath, $repositoryRoot)
$allowedOutputRoots = @(
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'release')),
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'artifacts')),
    [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'build'))
)

if (-not ($allowedOutputRoots | Where-Object {
    $outputFullPath.Equals($_, [StringComparison]::OrdinalIgnoreCase) -or
    $outputFullPath.StartsWith($_ + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
})) {
    throw "OutputPath must be under '$repositoryRoot\release', '$repositoryRoot\artifacts', or '$repositoryRoot\build'."
}

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
cp -Force '.\Other\release\*.bin' "$OutputPath\bin"
cp -Force '.\Other\release\*.dll' "$OutputPath\bin"
cp -Force '.\Other\release\*.exe' "$OutputPath\bin"
cp -Force '.\Other\release\*.dat' "$OutputPath\bin"

Write-Host
Write-Host 'Building Netch'

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
	-o ".\Netch\bin\$Configuration" `
	'.\Netch\Netch.csproj'
if ( -Not $? ) { exit $lastExitCode }
cp -Force ".\Netch\bin\$Configuration\Netch.exe" $OutputPath

Write-Host
Write-Host 'Building Redirector'

& $msbuild `
	-property:Configuration=$Configuration `
	-property:Platform=x64 `
	'.\Redirector\Redirector.vcxproj'
if ( -Not $? ) { exit $lastExitCode }
cp -Force ".\Redirector\bin\$Configuration\nfapi.dll"      "$OutputPath\bin"
cp -Force ".\Redirector\bin\$Configuration\Redirector.bin" "$OutputPath\bin"

Write-Host
Write-Host 'Building RouteHelper'

& $msbuild `
	-property:Configuration=$Configuration `
	-property:Platform=x64 `
	'.\RouteHelper\RouteHelper.vcxproj'
if ( -Not $? ) { exit $lastExitCode }
cp -Force ".\RouteHelper\bin\$Configuration\RouteHelper.bin" "$OutputPath\bin"

$requiredFiles = @(
    'Netch.exe',
    'bin\Redirector.bin',
    'bin\RouteHelper.bin',
    'bin\nfapi.dll',
    'bin\nfdriver.sys',
    'bin\aiodns.bin',
    'bin\aiodns.conf',
    'bin\pcap2socks.exe',
    'bin\tun2socks.exe',
    'bin\xray.exe',
    'bin\v2ray-sn.exe',
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
	rm -Force "$OutputPath\*.pdb"
	rm -Force "$OutputPath\*.xml"
}

Pop-Location
exit 0
