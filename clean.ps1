param (
    [switch]
    $KeepBuild
)

Push-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)

function Delete {
    param (
        [string]
        $Path
    )

    if (Test-Path $Path) {
        rm -Recurse -Force $Path | Out-Null
    }
}

Delete '.vs'
Delete 'artifacts'
if (-not $KeepBuild) {
    Delete 'build'
}
Delete 'release'
Delete 'NetchX\bin'
Delete 'NetchX\obj'
Delete 'Tests\bin'
Delete 'Tests\obj'
Delete 'Tests\TestResults'
Delete 'TestResults'
Delete 'Redirector\bin'
Delete 'Redirector\obj'
Delete 'RedirectorTester\bin'
Delete 'RedirectorTester\obj'
Delete 'RouteHelper\bin'
Delete 'RouteHelper\obj'

# Temporary objects emitted when the standalone native regression sources are
# compiled from the repository root.
Delete 'Based.obj'
Delete 'DNSHandler.obj'
Delete 'DNSHandlerQueueRegression.obj'
Delete 'EventHandler.obj'
Delete 'IcmpDelayConfigRegression.obj'
Delete 'IPEventHandler.obj'
Delete 'IPEventHandlerRegression.obj'
Delete 'Redirector.obj'
Delete 'SocksHelper.obj'
Delete 'SocksHelperRegression.obj'
Delete 'TCPHandler.obj'
Delete 'TcpHandlerHalfCloseRegression.obj'
Delete 'TcpHandlerShutdownRegression.obj'
Delete 'UdpDispatchRegression.obj'
Delete 'Utils.obj'
Delete 'vc140.pdb'

Delete 'NetchX\*.csproj.user'
Delete 'Redirector\*.vcxproj.user'
Delete 'RedirectorTester\*.csproj.user'
Delete 'RouteHelper\*.vcxproj.user'

.\other\clean.ps1

Pop-Location
exit $lastExitCode
