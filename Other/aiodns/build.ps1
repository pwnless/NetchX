$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)
try {
    New-Item -ItemType Directory -Path '..\release' -Force | Out-Null

    # Prefer the explicitly selected CGO compiler, then a compiler already on
    # PATH, followed by supported local MSYS2 installations.
    $gcc = if ($env:CC -and (Test-Path -LiteralPath $env:CC)) {
        $env:CC
    }
    else {
        (Get-Command gcc -ErrorAction SilentlyContinue).Source
    }
    if (-not $gcc) {
        $gccCandidates = @(
            'E:\msys64\ucrt64\bin\gcc.exe',
            'C:\msys64\ucrt64\bin\gcc.exe',
            'E:\msys64\mingw64\bin\gcc.exe',
            'C:\msys64\mingw64\bin\gcc.exe'
        ) | Where-Object { Test-Path -LiteralPath $_ }
        if ($gccCandidates.Count -gt 0) {
            $gcc = $gccCandidates[0]
        }
    }
    if (-not $gcc) {
        throw 'AioDNS requires a GCC-compatible CGO compiler. Install MSYS2 UCRT64 GCC or add gcc.exe to PATH.'
    }

    $compilerBin = Split-Path -Parent $gcc
    if (($Env:Path -split ';') -notcontains $compilerBin) {
        $Env:Path = "$compilerBin;$Env:Path"
    }

    # Prefer a caller-provided Go installation, then the current developer and
    # legacy locations. The CI workflow already places go.exe on PATH.
    $goCandidates = @()
    if ($env:NETCHX_GO_ROOT) {
        $goCandidates += Join-Path $env:NETCHX_GO_ROOT 'bin\go.exe'
    }
    $goCandidates += @(
        'E:\Program Files\Go\bin\go.exe',
        'D:\Program Files\Go\bin\go.exe'
    )
    $goCandidates = @($goCandidates | Where-Object { Test-Path -LiteralPath $_ })

    $go = (Get-Command go -ErrorAction SilentlyContinue).Source
    if (-not $go -and $goCandidates.Count -gt 0) {
        $go = $goCandidates[0]
    }
    if (-not $go) {
        throw 'AioDNS requires Go. Install Go or set NETCHX_GO_ROOT.'
    }

    $Env:CGO_ENABLED = '1'
    $Env:CC = $gcc
    $Env:GOOS = 'windows'
    $Env:GOARCH = 'amd64'

    # HTTP(S)_PROXY / ALL_PROXY are intentionally inherited rather than
    # hard-coded, allowing developers to use a local SOCKS or HTTP proxy
    # without affecting CI.
    & $go mod download
    if ($LASTEXITCODE -ne 0) {
        throw "AioDNS dependency download failed with exit code $LASTEXITCODE."
    }

    & $go test ./...
    if ($LASTEXITCODE -ne 0) {
        throw "AioDNS tests failed with exit code $LASTEXITCODE."
    }

    & $go build -a -buildmode=c-shared -trimpath -asmflags '-s -w' -ldflags '-s -w' -o '..\release\aiodns.bin'
    if ($LASTEXITCODE -ne 0) {
        throw "AioDNS shared-library build failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
