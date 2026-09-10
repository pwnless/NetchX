using System.Runtime.InteropServices;

namespace NetchX;

public static class NativeMethods
{
    [DllImport("dnsapi", EntryPoint = "DnsFlushResolverCache")]
    public static extern uint RefreshDNSCache();
}