using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES
{
    class Program
    {
        // Usage:
        //   ULTIMATE-CSharpencryptor.exe <input_file> <output_file> [--binary | --b64]
        //
        // Notes:
        //  --binary : encrypt raw bytes -> ciphertext bytes (recommended if you want a real .bin output)
        //  --b64    : (legacy-compatible) base64-encode input, encrypt the string (your original behavior)
        //
        // The program always prints AES Key & IV to screen (Base64 + C# byte[] format).

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                PrintUsage();
                return;
            }

            string inputPath = args[0];
            string outputPath = args[1];

            bool binaryMode = true; // default to binary output
            if (args.Length >= 3)
            {
                string mode = args[2].Trim().ToLowerInvariant();
                if (mode == "--binary") binaryMode = true;
                else if (mode == "--b64") binaryMode = false;
                else
                {
                    Console.WriteLine("[!] Unknown option: {0}", args[2]);
                    PrintUsage();
                    return;
                }
            }

            byte[] inputBytes;
            try
            {
                inputBytes = File.ReadAllBytes(inputPath);
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Error reading input: {0}", e.Message);
                PrintUsage();
                return;
            }

            using (Aes aes = Aes.Create())
            {
                // If you want consistent behavior with your Encrypt/Decrypt helpers:
                // set these explicitly (optional, but recommended).
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7; // safer than Zeros for arbitrary data

                aes.GenerateKey();
                aes.GenerateIV();

                // Print Key & IV to screen (Base64)
                Console.WriteLine("AES_Key (Base64): {0}", Convert.ToBase64String(aes.Key));
                Console.WriteLine("AES_IV  (Base64): {0}", Convert.ToBase64String(aes.IV));
                Console.WriteLine();

                // Print Key & IV as C# byte[] for easy copy/paste
                Console.WriteLine("AES Key (C#): {0}", ToCSharpByteArray("key", aes.Key));
                Console.WriteLine("AES IV  (C#): {0}", ToCSharpByteArray("iv", aes.IV));
                Console.WriteLine();

                byte[] encrypted;

                if (binaryMode)
                {
                    // Encrypt raw bytes -> ciphertext bytes (binary file output)
                    encrypted = EncryptBytesToBytes_Aes(inputBytes, aes.Key, aes.IV, aes.Padding, aes.Mode);
                }
                else
                {
                    // Legacy behavior: base64-encode input, encrypt as string
                    string originalB64 = Convert.ToBase64String(inputBytes);
                    encrypted = EncryptStringToBytes_Aes(originalB64, aes.Key, aes.IV, aes.Padding, aes.Mode);
                }

                try
                {
                    File.WriteAllBytes(outputPath, encrypted);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[!] Error writing output: {0}", e.Message);
                    PrintUsage();
                    return;
                }

                Console.WriteLine("[+] Wrote encrypted output: {0}", outputPath);
                Console.WriteLine("[+] Ciphertext length: {0} bytes", encrypted.Length);

                // Optional: quick roundtrip check (kept, but adjusted for mode)
                try
                {
                    if (binaryMode)
                    {
                        byte[] decrypted = DecryptBytesFromBytes_Aes(encrypted, aes.Key, aes.IV, aes.Padding, aes.Mode);
                        Console.WriteLine("[+] Roundtrip OK: {0}", ByteArraysEqual(inputBytes, decrypted));
                    }
                    else
                    {
                        string roundtripB64 = DecryptStringFromBytes_Aes(encrypted, aes.Key, aes.IV, aes.Padding, aes.Mode);
                        byte[] roundtripBytes = Convert.FromBase64String(roundtripB64);
                        Console.WriteLine("[+] Roundtrip OK: {0}", ByteArraysEqual(inputBytes, roundtripBytes));
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Roundtrip check failed: {0}", ex.Message);
                }
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine("[+] Usage:");
            Console.WriteLine("[+]   ULTIMATE-CSharpencryptor.exe <path_to_input_file> <output_file> [--binary | --b64]");
            Console.WriteLine("[+]");
            Console.WriteLine("[+] Examples:");
            Console.WriteLine("[+]   ULTIMATE-CSharpencryptor.exe payload.bin out.enc --binary");
            Console.WriteLine("[+]   ULTIMATE-CSharpencryptor.exe payload.bin out.enc --b64");
        }

        static string ToCSharpByteArray(string name, byte[] data)
        {
            var sb = new StringBuilder();
            sb.Append("byte[] ").Append(name).Append(" = new byte[").Append(data.Length).Append("] { ");

            for (int i = 0; i < data.Length; i++)
            {
                sb.AppendFormat("0x{0:x2}", data[i]);
                if (i != data.Length - 1) sb.Append(", ");
            }

            sb.Append(" };");
            return sb.ToString();
        }

        static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        // === Binary-safe AES encrypt/decrypt for arbitrary bytes ===
        static byte[] EncryptBytesToBytes_Aes(byte[] plainBytes, byte[] key, byte[] iv, PaddingMode padding, CipherMode mode)
        {
            if (plainBytes == null || plainBytes.Length == 0) throw new ArgumentNullException(nameof(plainBytes));
            if (key == null || key.Length == 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length == 0) throw new ArgumentNullException(nameof(iv));

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = padding;
                aesAlg.Mode = mode;

                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                using (var msEncrypt = new MemoryStream())
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                    csEncrypt.FlushFinalBlock();
                    return msEncrypt.ToArray();
                }
            }
        }

        static byte[] DecryptBytesFromBytes_Aes(byte[] cipherBytes, byte[] key, byte[] iv, PaddingMode padding, CipherMode mode)
        {
            if (cipherBytes == null || cipherBytes.Length == 0) throw new ArgumentNullException(nameof(cipherBytes));
            if (key == null || key.Length == 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length == 0) throw new ArgumentNullException(nameof(iv));

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = padding;
                aesAlg.Mode = mode;

                using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                using (var msDecrypt = new MemoryStream(cipherBytes))
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (var msPlain = new MemoryStream())
                {
                    csDecrypt.CopyTo(msPlain);
                    return msPlain.ToArray();
                }
            }
        }

        // === Your original string-based helpers, with explicit mode/padding ===
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] key, byte[] iv, PaddingMode padding, CipherMode mode)
        {
            if (plainText == null || plainText.Length == 0) throw new ArgumentNullException(nameof(plainText));
            if (key == null || key.Length == 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length == 0) throw new ArgumentNullException(nameof(iv));

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = padding;
                aesAlg.Mode = mode;

                using (ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                using (MemoryStream msEncrypt = new MemoryStream())
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt, Encoding.UTF8))
                {
                    swEncrypt.Write(plainText);
                    swEncrypt.Flush();
                    csEncrypt.FlushFinalBlock();
                    return msEncrypt.ToArray();
                }
            }
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] key, byte[] iv, PaddingMode padding, CipherMode mode)
        {
            if (cipherText == null || cipherText.Length == 0) throw new ArgumentNullException(nameof(cipherText));
            if (key == null || key.Length == 0) throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length == 0) throw new ArgumentNullException(nameof(iv));

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = padding;
                aesAlg.Mode = mode;

                using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }
    }
}
