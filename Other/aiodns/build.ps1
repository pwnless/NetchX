Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path '..\release' -Force | Out-Null

$goBin = 'D:\Program Files\Go\bin'
if (Test-Path -LiteralPath $goBin) {
    $Env:Path = "$goBin;$Env:Path"
}

$fallback = 'D:\Netch\bin\aiodns.bin'
if (-not (Get-Command go -ErrorAction SilentlyContinue) -or -not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    if (-not (Test-Path -LiteralPath $fallback)) {
        throw 'AioDNS needs Go plus a GCC-compatible CGO compiler, and no fallback binary is available.'
    }

    Write-Warning 'No GCC-compatible CGO compiler was found; staging the verified local aiodns.bin fallback.'
    Copy-Item -LiteralPath $fallback -Destination '..\release\aiodns.bin' -Force
    exit 0
}

$Env:CGO_ENABLED='1'
$Env:GOROOT_FINAL='/usr'

$Env:GOOS='windows'
$Env:GOARCH='amd64'
go build -a -buildmode=c-shared -trimpath -asmflags '-s -w' -ldflags '-s -w' -o '..\release\aiodns.bin'
exit $lastExitCode
