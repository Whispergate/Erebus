# Shellcraft
# A QoL tool to obfuscate shellcode.
# In the future will be able to chain encoding/encryption/compression methods.
# ~ @0xLegacyy (Jordan Jay)
import argparse
import zlib
import argparse
import base64
import logging
import os
import pyfiglet
import random

from rich.console import Console
from rich.theme import Theme
from rich.logging import RichHandler

from binascii import hexlify
from itertools import cycle
from os import urandom
from os.path import isfile
from string import hexdigits

from Crypto.Cipher import AES, ARC4, ChaCha20, Salsa20
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


theme = Theme({
    "success" : "spring_green3",
    "info" : "cornflower_blue",
    "error" : "red",
    "exception" : "red",
})
console = Console(theme=theme, color_system="auto")

DEBUG = False

log_path = "logs"
debug_path = "logs/debug_logs.log"
session_path = "logs/session_logs.log"
if not os.path.exists(log_path):
    os.mkdir(log_path)

if not os.path.exists(debug_path):
    with open(debug_path, 'w'): pass

if not os.path.exists(session_path):
    with open(session_path, 'w'): pass

logging.basicConfig(
    level="DEBUG",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(rich_tracebacks=True),
        logging.FileHandler(debug_path, mode='a', encoding="utf-8"),
        logging.FileHandler(session_path, mode='w', encoding="utf-8"),
    ],
)

logger = logging.getLogger("rich")


# global vars
OUTPUT_FORMATS = [
    "c",
    "csharp",
    "nim",
    "go",
    "py",
    "ps1",
    "vba",
    "vbscript",
    "raw",
    "rust",
    "js",
    "zig"
]


CIPHERS = [
    "aes_128",
    "aes_ecb",
    "aes_cbc",
    "chacha20",
    "rc4",
    "salsa20",
    "xor",
    "xor_complex"
]

ENCODING = [
    "alpha32",
    "ascii85",
    "base64",
    "words256"
]

COMPRESSION = [
    "lznt",
    "rle",
]

VERSION = "v2.0 - Release"

def show_banner():
    banner = pyfiglet.figlet_format("Shellcrypt", font="slant", justify="left")
    console.print(f"[bold yellow]{banner}{VERSION}\n[/bold yellow]")
    console.print("By: @0xLegacyy (Jordan Jay)\n", style="green4")


class Log:
    """Handles all styled terminal output."""
    def __init__(self):
        pass

    def logSuccess(msg: str):
        """Logs msg to the terminal with a green [+] appended. Used to show task success."""
        return logger.debug(f"[+] {msg}")

    def logInfo(msg: str):
        """Logs msg to the terminal with a blue [*] appended. Used to show task status / info."""
        return logger.info(f"[!] {msg}")

    def logDebug(msg: str):
        """Logs msg to the terminal with a magenta [debug] appended. Used for debug info."""
        if DEBUG:
            return logger.debug(f"[+] {msg}")

    def logError(msg: str):
        """Logs msg to the terminal with a red [!] appended. Used for error messages."""
        return logger.error(f"[-] {msg}")

    def log_exception(msg: str):
        """Logs msg to the terminal with a red [!!] appended. Used to show error messages."""
        return logger.exception(f"[!!] {msg}")


class ShellcodeFormatter:
    """Generates shellcode output in various formats."""
    def __init__(self):
        self.__format_handlers = {
            "c": self.__output_c,
            "csharp": self.__output_csharp,
            "nim": self.__output_nim,
            "go": self.__output_go,
            "py": self.__output_py,
            "ps1": self.__output_ps1,
            "vba": self.__output_vba,
            "vbscript": self.__output_vbscript,
            "raw": self.__output_raw,
            "rust": self.__output_rust,
            "js": self.__output_js,
            "zig": self.__output_zig
        }

    def __generate_array_contents(self, input_bytes: bytearray, string_format=False) -> str:
        """Generates formatted shellcode from bytearray."""
        output = ""
        if not string_format:
            for i in range(len(input_bytes) - 1):
                if i % 15 == 0:
                    output += "\n\t"
                output += f"0x{input_bytes[i]:0>2x},"
            output += f"0x{input_bytes[-1]:0>2x}"
            return output[1:]
        else:
            for i in range(len(input_bytes) - 1):
                if i % 15 == 0:
                    output += "\n"
                output += f"\\x{input_bytes[i]:0>2x}"
            output += f"\\x{input_bytes[-1]:0>2x}"
            return output[1:]

    def __output_format(self, arrays: dict, template: str, array_format="unsigned char") -> str:
        """Generate shellcode in specified format."""
        output = ""
        for array_name, array in arrays.items():
            output += f"{array_format} {array_name}[{len(array)}] = {{\n"
            output += self.__generate_array_contents(array)
            output += "\n};\n\n"
        return output

    def __output_c(self, arrays: dict) -> str:
        return self.__output_format(arrays, "c")

    def __output_rust(self, arrays: dict) -> str:
        return self.__output_format(arrays, "rust", array_format="let")

    def __output_csharp(self, arrays: dict) -> str:
        return self.__output_format(arrays, "csharp", array_format="byte[]")

    def __output_nim(self, arrays: dict) -> str:
        output = ""
        for array_name, array in arrays.items():
            output += f"var {array_name}: array[{len(array)}, byte] = [\n"
            output += "\tbyte " + self.__generate_array_contents(array)[1:]
            output += "\n]\n\n"
        return output

    def __output_go(self, arrays: dict) -> str:
        return self.__output_format(arrays, "go", array_format="[]byte")

    def __output_py(self, arrays: dict) -> str:
        output = ""
        for array_name, array in arrays.items():
            output += f"{array_name} = b\"\"\""
            output += self.__generate_array_contents(array, string_format=True)
            output += "\"\"\"\n\n"
        return output

    def __output_ps1(self, arrays: dict) -> str:
        output = ""
        for array_name, array in arrays.items():
            output += f"[Byte[]] ${array_name} = "
            output += self.__generate_array_contents(array)[1:]
            output += "\n\n"
        return output

    def __output_vba(self, arrays: dict) -> str:
        output = ""
        for array_name, array in arrays.items():
            output += f"{array_name} = Array("
            line_length = len(output)
            for i, x in enumerate(array):
                if line_length + 5 > 1022:
                    output += "_\n"
                    line_length = 0
                output += f"{x},"
                line_length += len(f"{x},")
            if line_length + 4 > 1023:
                output += "_\n"
            output += f"{x})\n\n"
        return output

    def __output_vbscript(self, arrays: dict) -> str:
        output = ""
        for array_name, array in arrays.items():
            output += f"{array_name}="
            output += "".join([f"Chr({str(c)})&" for c in array])[:-1]
            output += "\n\n"
        return output

    def __output_js(self, arrays: dict) -> str:
        """JavaScript output."""
        output = ""
        for array_name, array in arrays.items():
            output += f"const {array_name} = new Uint8Array({len(array)}); \n"
            output += f"{array_name}.set(["
            output += self.__generate_array_contents(array)
            output += "]);\n\n"
        return output

    def __output_zig(self, arrays: dict) -> str:
        """Zig output."""
        output = ""
        for array_name, array in arrays.items():
            output += f"var {array_name} = []u8{{\n"
            output += self.__generate_array_contents(array)
            output += "\n};\n\n"
        return output

    def __output_raw(self, arrays: dict) -> str:
        return arrays["sh3llc0d3"]

    def generate(self, output_format: str, arrays: dict) -> str:
        """Generates the formatted shellcode based on the output format."""
        return self.__format_handlers.get(output_format)(arrays)


class Encrypt:
    """ Consolidates encryption into a single class. """
    def __init__(self):
        super(Encrypt, self).__init__()
        self.__encryption_handlers = {
            "xor":         self.__xor,
            "xor_complex": self.__xor_complex,
            "aes_128":     self.__aes_128,
            "aes_ecb":     self.__aes_ecb,
            "aes_cbc":     self.__aes_cbc,
            "rc4":         self.__rc4,
            "chacha20":    self.__chacha20,
            "salsa20":     self.__salsa20
        }
        return

    def __random_key(self) -> int:
        self.seed = random.randint(0, 2**32 - 1)  
        
        LCG_A = 1664525  # Multiplier
        LCG_C = 1013904223  # Increment
        LCG_M = 2**32  # Modulus (2^32)

        self.seed = (LCG_A * self.seed + LCG_C) % LCG_M
        return self.seed & 0xFF

    def encrypt(self, cipher:str, plaintext:bytearray, key:bytearray, nonce:bytearray = None) -> bytearray:
        """ Encrypts plaintext with the user-specified cipher.
            This has been written this way to support chaining of
            multiple encryption methods in the future.
        :param cipher: cipher to use, e.g. 'xor'/'aes'
        :param plaintext: bytearray containing our plaintext
        :param key: bytearray containing our encryption key
        :param nonce: bytearray containing nonce for aes etc.
                      if none will be generated on the fly
        :return ciphertext: bytearray containing encrypted plaintext
        """
        # If nonce not specified, generate one, otherwise use the specified one.
        self.nonce = urandom(16) if nonce is None else nonce
        self.key = key
        # cipher is already validated (check argument validation section).
        return self.__encryption_handlers[cipher](plaintext)

    def __xor(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext with a repeating XOR key.
        :param plaintext: bytearray containing our plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        return bytearray(a ^ b for (a, b) in zip(plaintext, cycle(self.key)))

    def __xor_complex(self, plaintext: bytearray) -> bytearray:
        """
        XOR Encrypts/Decrypts given shellcode using a Linear Congruential Generator (LCG)
        """
        encrypted_shellcode = bytearray()
        for byte in plaintext:
            random_key = self.__random_key()
            encrypted_shellcode.append(byte ^ random_key)

        return encrypted_shellcode

    def __aes_128(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext with AES-128 in CBC mode.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        aes_cipher = AES.new(self.key, AES.MODE_CBC, self.nonce)
        plaintext = pad(plaintext, 16)
        return bytearray(aes_cipher.encrypt(plaintext))

    def __rc4(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext via RC4.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        rc4_cipher = ARC4.new(self.key)
        return rc4_cipher.encrypt(plaintext)

    def __chacha20(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext via ChaCha20.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        chacha20_cipher = ChaCha20.new(key=self.key)
        return chacha20_cipher.encrypt(plaintext)

    def __salsa20(self, plaintext:bytearray) -> bytearray:
        """ Private method to encrypt the input plaintext via Salsa20.
        :param plaintext: bytearray containing plaintext
        :return ciphertext: bytearray containing encrypted plaintext
        """
        salsa20_cipher = Salsa20.new(key=self.key)
        return salsa20_cipher.encrypt(plaintext)

    def __aes_ecb(self, plaintext:bytearray) -> bytearray:
        cipher = AES.new(self.key, AES.MODE_ECB)
        padding_length = 16 - len(plaintext) % 16
        padded_shellcode = plaintext + bytearray([padding_length] * padding_length)
        return cipher.encrypt(padded_shellcode)

    def __aes_cbc(self, plaintext:bytearray) -> bytearray:
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        padding_length = 16 - len(plaintext) % 16
        padded_shellcode = plaintext + bytearray([padding_length] * padding_length)

        encrypted_shellcode = cipher.encrypt(padded_shellcode)
        return bytearray(iv) + bytearray(encrypted_shellcode)


class Compress:
    def __init__(self):
        self.__compression_handlers = {
            "lznt": self.__lznt_compress,
            "rle":  self.__rle_compress
        }
        self.__decompression_handlers = {
            "lznt": self.__lznt_decompress,
            "rle":  self.__rle_decompress
        }

    def compress(self, method: str, data: bytearray) -> bytearray:
        """Compress data using specified method."""
        return self.__compression_handlers.get(method)(data)

    def decompress(self, method: str, data: bytearray) -> bytearray:
        """Decompress data using specified method."""
        return self.__decompression_handlers.get(method)(data)

    def __lznt_compress(self, data: bytearray) -> bytearray:
        """LZNT compression."""
        return bytearray(zlib.compress(data))

    def __lznt_decompress(self, data: bytearray) -> bytearray:
        """LZNT decompression."""
        return bytearray(zlib.decompress(data))

    def __rle_compress(self, data: bytearray) -> bytearray:
        """Run-Length Encoding (RLE) compression."""
        compressed = bytearray()
        index = 0
        while index < len(data):
            byte = data[index]
            count = 1
            while index + 1 < len(data) and data[index + 1] == byte:
                count += 1
                index += 1
            compressed.extend([byte, count])
            index += 1
        return compressed

    def __rle_decompress(self, data: bytearray) -> bytearray:
        """Run-Length Encoding (RLE) decompression."""
        decompressed = bytearray()
        for i in range(0, len(data), 2):
            byte, count = data[i], data[i + 1]
            decompressed.extend([byte] * count)
        return decompressed


class Encode:
    def __init__(self):
        self.__encoding_handlers = {
            "base64": self.__base64_encode,
            "ascii85": self.__ascii85_encode,
            "alpha32": self.__alpha32_encode,
            "words256": self.__words256_encode
        }
        self.__decoding_handlers = {
            "base64": self.__base64_decode,
            "ascii85": self.__ascii85_decode,
            "alpha32": self.__alpha32_decode,
            "words256": self.__words256_decode
        }

    def encode(self, encoding: str, data: bytearray) -> bytearray:
        """Encode data using specified encoding."""
        handler = self.__encoding_handlers.get(encoding)
        if handler:
            return handler(data)
        raise ValueError(f"Unsupported encoding: {encoding}")

    def decode(self, decoding: str, data: bytearray) -> bytearray:
        """Decode data using specified decoding."""
        handler = self.__decoding_handlers.get(decoding)
        if handler:
            return handler(data)
        raise ValueError(f"Unsupported decoding: {decoding}")

    def __base64_encode(self, data: bytearray) -> bytearray:
        """Base64 encoding."""
        return bytearray(base64.b64encode(data))

    def __base64_decode(self, data: bytearray) -> bytearray:
        """Base64 decoding."""
        return bytearray(base64.b64decode(data))

    def __ascii85_encode(self, data: bytearray) -> bytearray:
        """ASCII85 encoding."""
        return bytearray(base64.a85encode(data))

    def __ascii85_decode(self, data: bytearray) -> bytearray:
        """ASCII85 decoding."""
        return bytearray(base64.a85decode(data))

    def __alpha32_encode(self, data: bytearray) -> bytearray:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
        encoded = bytearray()
        for byte in data:
            encoded.extend(alphabet[byte % len(alphabet)].encode())
        return encoded

    def __alpha32_decode(self, data: bytearray) -> bytearray:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
        decoded = bytearray()
        for char in data:
            decoded.append(alphabet.index(chr(char)))
        return decoded

    def __words256_encode(self, data: bytearray) -> bytearray:
        words = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot",
                "Golf", "Hotel", "India", "Juliet", "Kilo", "Lima", "Mike",
                "November", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango",
                "Uniform", "Victor", "Whiskey", "X-ray", "Yankee", "Zulu"]
        encoded = bytearray()
        for byte in data:
            encoded.extend(words[byte % len(words)].encode() + b" ")
        return encoded

    def __words256_decode(self, data: bytearray) -> bytearray:
        words = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot",
                "Golf", "Hotel", "India", "Juliet", "Kilo", "Lima", "Mike",
                "November", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango",
                "Uniform", "Victor", "Whiskey", "X-ray", "Yankee", "Zulu"]
        decoded = bytearray()
        word = b""
        for byte in data:
            word += bytes([byte])
            if word.endswith(b" "):  # Word boundary (space)
                decoded.append(words.index(word.decode().strip()))
                word = b""
        return decoded


def parse_args():
    # Parse arguments with additional features
    # TODO: Add decryption routines in the future

    argparser = argparse.ArgumentParser(prog="shellcrypt")

    # Required argument: Input file
    argparser.add_argument("-i", "--input", help="Path to file to be encrypted.", required=True)

    # Encryption related options
    argparser.add_argument("-e", "--encrypt", default="xor", help="Encryption method to use, default 'xor'.")
    argparser.add_argument("--decrypt", action="store_true", help="Enable decryption functionality (not yet implemented).")

    # Encoding related options
    argparser.add_argument("-d", "--encode", default=None, help="Encoding method to use, default None.")

    # Compression related options
    argparser.add_argument("-c", "--compress", default=None, help="Compression method to use.")

    # Key and nonce options
    argparser.add_argument("-k", "--key", help="Encryption key in hex format, default (random 16 bytes).")
    argparser.add_argument("-n", "--nonce", help="Encryption nonce in hex format, default (random 16 bytes).")

    # Format related options
    argparser.add_argument("-f", "--format", help="Output format, specify --formats for a list of formats.")

    # Info-related arguments
    argparser.add_argument("--formats", action="store_true", help="Show a list of valid formats")
    argparser.add_argument("--ciphers", action="store_true", help="Show a list of valid ciphers")
    argparser.add_argument("--encoders", action="store_true", help="Show a list of valid encoders")
    argparser.add_argument("--compressors", action="store_true", help="Show a list of valid compressors")

    # Output file and version
    argparser.add_argument("-o", "--output", help="Path to output file")
    argparser.add_argument("-v", "--version", action="store_true", help="Shows the version and exits")

    # Additional Features
    # Preserve null bytes during XOR encryption
    argparser.add_argument("--preserve-null", action="store_true", help="Avoid XORing null bytes during XOR encryption.")

    # Specify key length (if greater than 16)
    argparser.add_argument("--key-length", type=int, default=16, help="Specify the key length in bytes (default is 16).")

    return argparser.parse_args()

def print_available_options(option_type, options, exit_on_print=True):
    print(f"The following {option_type} are available:")
    for option in options:
        print(f" - {option}")
    if exit_on_print:
        exit()

def validate_input_file(input_file):
    if input_file is None:
        Log.logError("Must specify an input file e.g. -i shellcode.bin (specify --help for more info)")
        exit()
    if not isfile(input_file):
        Log.logError(f"Input file '{input_file}' does not exist.")
        exit()
    Log.logSuccess(f"Input file: '{input_file}'")

def validate_and_get_key(key, encrypt_type):
    if key is None:
        return urandom(32)

    if len(key) < 2 or len(key) % 2 == 1 or any(i not in hexdigits for i in key):
        Log.logError("Key must be valid byte(s) in hex format (e.g. 4141).")
        exit()

    if encrypt_type == "aes" and len(key) != 32:
        Log.logError("AES-128 key must be exactly 16 bytes long.")
        exit()

    return bytearray.fromhex(key)

def validate_and_get_nonce(nonce):
    if nonce is None:
        return urandom(16)

    if len(nonce) != 32 or any(i not in hexdigits for i in nonce):
        Log.logError("Nonce must be 16 valid bytes in hex format (e.g. 7468697369736d616c6963696f757321)")
        exit()

    return bytearray.fromhex(nonce)

def process_encoding_and_compression(input_bytes, args, encoder, compressor):
    if args.encode:
        input_bytes = encoder.encode(args.encode, input_bytes)
    if args.compress:
        input_bytes = compressor.compress(args.compress, input_bytes)
    return input_bytes

def main():
    # Show banner and parse arguments
    show_banner()
    args = parse_args()

    # --------- Info-only arguments ---------
    if args.formats:
        print_available_options("formats", OUTPUT_FORMATS)
    if args.ciphers:
        print_available_options("ciphers", CIPHERS)
    if args.encoders:
        print_available_options("encoders", ENCODING)
    if args.compressors:
        print_available_options("compressors", COMPRESSION)
    if args.version:
        print(VERSION)
        exit()

    # --------- Argument Validation ---------
    Log.logDebug(msg="Validating arguments")

    validate_input_file(args.input)

    if args.format not in OUTPUT_FORMATS:
        Log.logError("Invalid format specified, please specify a valid format e.g. -f c (--formats gives a list of valid formats)")
        exit()
    Log.logSuccess(f"Output format: {args.format}")

    if args.encrypt not in CIPHERS:
        Log.logError("Invalid cipher specified, please specify a valid cipher e.g. -e xor (--ciphers gives a list of valid ciphers)")
        exit()

    if args.encode and args.encode not in ENCODING:
        Log.logError("Invalid encoder specified, please specify a valid encoder e.g. -d ascii85 (--encoders gives a list of valid encoders)")
        exit()

    if args.compress and args.compress not in COMPRESSION:
        Log.logError("Invalid compression specified, please specify a valid compression e.g. -c lznt (--compressors gives a list of valid compressors)")
        exit()

    Log.logSuccess(f"Output Encoding: {args.encode}")
    Log.logSuccess(f"Output Encryption: {args.encrypt}")
    Log.logSuccess(f"Output Compression: {args.compress}")

    key = validate_and_get_key(args.key, args.encrypt)
    Log.logSuccess(f"Using key: {hexlify(key).decode()}")

    nonce = validate_and_get_nonce(args.nonce)
    if args.encrypt == "aes":
        Log.logSuccess(f"Using nonce: {hexlify(nonce).decode()}")

    Log.logDebug("Arguments validated")

    # --------- Read Input File ---------
    with open(args.input, "rb") as input_handle:
        input_bytes = input_handle.read()

    # --------- Input File Processing ---------
    cryptor = Encrypt()
    compressor = Compress()
    encoder = Encode()

    input_bytes = cryptor.encrypt(args.encrypt, input_bytes, key, nonce)
    input_bytes = process_encoding_and_compression(input_bytes, args, encoder, compressor)

    Log.logSuccess(f"Successfully processed input file ({len(input_bytes)} bytes)")

    # --------- Output Generation ---------
    arrays = {"key": key}
    if args.encrypt in ["aes_128", "aes_ecb", "aes_cbc"]:
        arrays["nonce"] = nonce
    arrays["sh3llc0d3"] = input_bytes

    # Generate formatted output
    shellcode_formatter = ShellcodeFormatter()
    output = shellcode_formatter.generate(args.format, arrays)

    # --------- Output ---------
    if args.output is None:
        console.print(output.decode("latin1") if isinstance(output, bytearray) else output)
        exit()

    write_mode = "wb" if isinstance(output, bytearray) else "w"
    with open(args.output, write_mode) as file_handle:
        file_handle.write(output)

    Log.logSuccess(f"Output written to '{args.output}'")

if __name__ == "__main__":
    main()
