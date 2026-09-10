Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path '..\release' -Force | Out-Null

$goBin = 'D:\Program Files\Go\bin'
if (Test-Path -LiteralPath $goBin) {
    $Env:Path = "$goBin;$Env:Path"
}

$fallback = 'D:\Netch\bin\v2ray-sn.exe'
$expectedFallbackHash = 'a219f435671fb214c0c530084c65e576fdc1404f40b187b5586e869d2a3e4dff'

function Stage-LegacyFallback {
    if (-not (Test-Path -LiteralPath $fallback -PathType Leaf)) {
        throw "v2ray-sn fallback binary is missing: $fallback"
    }

    $actualHash = (Get-FileHash -LiteralPath $fallback -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedFallbackHash) {
        throw "v2ray-sn fallback binary did not match the pinned SHA-256: $fallback"
    }

    Copy-Item -LiteralPath $fallback -Destination '..\release\v2ray-sn.exe' -Force
}

if ($Env:NETCH_BUILD_V2RAY_FROM_SOURCE -ne '1') {
    Write-Warning 'Staging the local v2ray-sn fallback. Set NETCH_BUILD_V2RAY_FROM_SOURCE=1 to rebuild its legacy fork from source.'
    Stage-LegacyFallback
    exit 0
}

try {
    if (-not (Get-Command go -ErrorAction Stop)) {
        throw 'Go is not available.'
    }

    git clone --depth 1 --branch 'v5.0.16' https://github.com/SagerNet/v2ray-core.git src
    if (-not $?) {
        throw 'Failed to clone SagerNet/v2ray-core.'
    }
    Set-Location src

    Invoke-WebRequest -Uri 'https://gist.githubusercontent.com/H1JK/b3165a99b635dcc06101690e4c43b5fd/raw/691b471f3b395a949d03a3d064d93d319d4997b7/ssr.go' -OutFile '.\proxy\shadowsocks\plugin\self\ssr.go' -ErrorAction Stop
    Invoke-WebRequest -Uri 'https://gist.githubusercontent.com/H1JK/b3165a99b635dcc06101690e4c43b5fd/raw/691b471f3b395a949d03a3d064d93d319d4997b7/obfs.go' -OutFile '.\proxy\shadowsocks\plugin\self\obfs.go' -ErrorAction Stop

    Remove-Item '.\common\buf\io.go' -ErrorAction Stop
    Remove-Item '.\common\buf\readv_reader.go' -ErrorAction Stop
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SagerNet/v2ray-core/2711fd1/common/buf/io.go' -OutFile '.\common\buf\io.go' -ErrorAction Stop
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SagerNet/v2ray-core/2711fd1/common/buf/readv_reader.go' -OutFile '.\common\buf\readv_reader.go' -ErrorAction Stop

    $Env:CGO_ENABLED='0'
    $Env:GOROOT_FINAL='/usr'
    $Env:GOOS='windows'
    $Env:GOARCH='amd64'
    go mod tidy
    go build -a -trimpath -asmflags '-s -w' -ldflags '-s -w -buildid=' -o '..\..\release\v2ray-sn.exe' '.\main'
    if (-not $?) {
        throw 'v2ray-sn build failed.'
    }
}
catch {
    Write-Warning "v2ray-sn source build failed ($($_.Exception.Message)); staging the local fallback binary."
    Stage-LegacyFallback
}
finally {
    Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)
    if (Test-Path -LiteralPath '.\src') {
        Remove-Item -LiteralPath '.\src' -Recurse -Force
    }
}
