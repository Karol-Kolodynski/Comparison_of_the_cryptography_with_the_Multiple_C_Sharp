using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel;

namespace RSA_LICZENIE_SLOW_C_
{
    public class Szyfrowanie
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(
            IntPtr hProcess,
            out FILETIME creationTime,
            out FILETIME exitTime,
            out FILETIME kernelTime,
            out FILETIME userTime);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetProcessMemoryInfo(
            IntPtr hProcess,
            out PROCESS_MEMORY_COUNTERS counters,
            uint cb);

        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential, Size = 72)]
        public struct PROCESS_MEMORY_COUNTERS
        {
            public uint cb;
            public uint PageFaultCount;
            public UIntPtr PeakWorkingSetSize;
            public UIntPtr WorkingSetSize;
            public UIntPtr QuotaPeakPagedPoolUsage;
            public UIntPtr QuotaPagedPoolUsage;
            public UIntPtr QuotaPeakNonPagedPoolUsage;
            public UIntPtr QuotaNonPagedPoolUsage;
            public UIntPtr PagefileUsage;
            public UIntPtr PeakPagefileUsage;
        }


        public void GetProcessorTimes(out FILETIME userTime, out FILETIME kernelTime)
        {
            IntPtr process = Process.GetCurrentProcess().Handle;
            if (!GetProcessTimes(process, out _, out _, out kernelTime, out userTime))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        public double FileTimeToSeconds(FILETIME ft)
        {
            long time = ((long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            return time / 10000000.0;
        }

        public void PrintResourceUsage(double cpuUsage, PROCESS_MEMORY_COUNTERS pmc)
        {
            Console.WriteLine($"Uzycie procesora: {cpuUsage:F2}%");
            Console.WriteLine($"Uzycie pamieci RAM: {pmc.WorkingSetSize} B");
        }

        private bool GetProcessMemoryInfoWrapper(IntPtr hProcess, out PROCESS_MEMORY_COUNTERS counters, uint cb)
        {
            return GetProcessMemoryInfo(hProcess, out counters, cb);
        }

        private byte[] EncryptAesCtr(byte[] plaintext, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                return ProcessCtr(plaintext, iv, aes.CreateEncryptor());
            }
        }

        private byte[] DecryptAesCtr(byte[] ciphertext, byte[] key, byte[] iv)
        {
            return EncryptAesCtr(ciphertext, key, iv);
        }

        private byte[] ProcessCtr(byte[] input, byte[] iv, ICryptoTransform transform)
        {
            byte[] counter = (byte[])iv.Clone();
            byte[] output = new byte[input.Length];
            int blockSize = transform.OutputBlockSize;

            for (int i = 0; i < input.Length; i += blockSize)
            {
                byte[] counterBlock = transform.TransformFinalBlock(counter, 0, counter.Length);
                IncrementCounter(counter);

                int length = Math.Min(blockSize, input.Length - i);
                for (int j = 0; j < length; j++)
                    output[i + j] = (byte)(input[i + j] ^ counterBlock[j]);
            }
            return output;
        }

        private void IncrementCounter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
                if (++counter[i] != 0)
                    break;
        }

        private byte[] HexEncode(byte[] input)
        {
            return Encoding.ASCII.GetBytes(BitConverter.ToString(input).Replace("-", ""));
        }

        private byte[] HexDecode(byte[] input)
        {
            string hex = Encoding.ASCII.GetString(input);
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }


        public string GenerateRandomText(int minLength, int maxLength)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
            Random random = new Random();
            int length = random.Next(minLength, maxLength + 1);
            char[] result = new char[length];

            for (int i = 0; i < length; i++)
                result[i] = chars[random.Next(chars.Length)];

            return new string(result);
        }



        public void EncryptDecryptAES(string plaintext, int keySize)
        {
            using (Aes aes = Aes.Create())
            {
                if (keySize != 128 && keySize != 192 && keySize != 256)
                {
                    Console.WriteLine("Nieprawidlowy rozmiar klucza AES.");
                    return;
                }

                aes.KeySize = keySize;
                aes.GenerateKey();
                aes.GenerateIV();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                Console.WriteLine($"Klucz AES (hex):\n{BitConverter.ToString(aes.Key).Replace("-", "")}");
                Console.WriteLine($"Tekst oryginalny: {plaintext}");

                byte[] plainBytes = HexEncode(Encoding.UTF8.GetBytes(plaintext));
                byte[] cipher = EncryptAesCtr(plainBytes, aes.Key, aes.IV);
                Console.WriteLine($"Zaszyfrowany tekst (hex): {BitConverter.ToString(cipher).Replace("-", "")}");

                byte[] decrypted = DecryptAesCtr(cipher, aes.Key, aes.IV);
                string decodedRecovered = Encoding.UTF8.GetString(HexDecode(decrypted));

                Console.WriteLine($"IV (hex):\n{BitConverter.ToString(aes.IV).Replace("-", "")}");
                Console.WriteLine($"Tekst odszyfrowany: {decodedRecovered}");

                if (plaintext != decodedRecovered)
                    Console.WriteLine("Blad: Tekst odszyfrowany rozni sie od oryginalnego!");
            }
        }


        private void PrintRSAParameters(RSAParameters parameters)
        {
            Console.WriteLine($"Modulus: {BitConverter.ToString(parameters.Modulus).Replace("-", "")}");
            Console.WriteLine($"Exponent: {BitConverter.ToString(parameters.Exponent).Replace("-", "")}");
            if (parameters.D != null)
                Console.WriteLine($"D: {BitConverter.ToString(parameters.D).Replace("-", "")}");
        }
        public void EncryptDecryptRSA(string plaintext, int keySize)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize))
            {
                RSAParameters publicKey = rsa.ExportParameters(false);
                RSAParameters privateKey = rsa.ExportParameters(true);

                Console.WriteLine("Prywatny klucz RSA (hex):");
                PrintRSAParameters(privateKey);
                Console.WriteLine("Publiczny klucz RSA (hex):");
                PrintRSAParameters(publicKey);

                Console.WriteLine($"Tekst oryginalny: {plaintext}");

                byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
                byte[] encrypted = rsa.Encrypt(plainBytes, true);
                Console.WriteLine($"Zaszyfrowany tekst (hex): {BitConverter.ToString(encrypted).Replace("-", "")}");

                byte[] decrypted = rsa.Decrypt(encrypted, true);
                string decryptedText = Encoding.UTF8.GetString(decrypted);
                Console.WriteLine($"Tekst odszyfrowany: {decryptedText}");

                if (plaintext != decryptedText)
                    Console.WriteLine("Blad: Tekst odszyfrowany rozni sie od oryginalnego!");
            }
        }

        

        

        





        public void SzyfrowanieMetoda()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Random rand = new Random();
            Console.WriteLine("Wybierz rodzaj szyfrowania: RSA lub AES");
            string choice = Console.ReadLine().ToUpper();

            if (choice == "RSA" || choice == "R")
            {
                Console.WriteLine("Czy chcesz podac wlasny tekst? (T/N)");
                char yn = Console.ReadKey().KeyChar;
                Console.WriteLine();

                FILETIME userStart, kernelStart, userEnd, kernelEnd;
                PROCESS_MEMORY_COUNTERS pmcStart, pmcEnd;
                Stopwatch stopwatch = new Stopwatch();

                if (yn == 'T' || yn == 't')
                {
                    Console.WriteLine("Podaj tekst:");
                    string plaintext = Console.ReadLine();

                    Console.WriteLine("Podaj dlugosc klucza 512, 1024, 2048 lub 4096: ");
                    int keySize = int.Parse(Console.ReadLine());

                    GetProcessorTimes(out userStart, out kernelStart);
                    GetProcessMemoryInfoWrapper(Process.GetCurrentProcess().Handle, out pmcStart, (uint)Marshal.SizeOf<PROCESS_MEMORY_COUNTERS>());
                    stopwatch.Start();

                    EncryptDecryptRSA(plaintext, keySize);

                    stopwatch.Stop();
                    GetProcessorTimes(out userEnd, out kernelEnd);
                    GetProcessMemoryInfoWrapper(Process.GetCurrentProcess().Handle, out pmcEnd, (uint)Marshal.SizeOf<PROCESS_MEMORY_COUNTERS>());

                    double userTime = FileTimeToSeconds(userEnd) - FileTimeToSeconds(userStart);
                    double kernelTime = FileTimeToSeconds(kernelEnd) - FileTimeToSeconds(kernelStart);
                    double cpuUsage = (userTime + kernelTime) / stopwatch.Elapsed.TotalSeconds * 100;

                    Console.WriteLine("\n=== Statystyki wydajnosci ===");
                    Console.WriteLine($"Czas wykonania: {stopwatch.Elapsed.TotalSeconds} sekund");
                    PrintResourceUsage(cpuUsage, pmcEnd);
                }
                else
                {
                    Console.WriteLine("Podaj ilosc hasel:");
                    int ilosc = int.Parse(Console.ReadLine());

                    Console.WriteLine("Podaj dlugosc klucza 512, 1024, 2048 lub 4096: ");
                    int keySize = int.Parse(Console.ReadLine());

                    Console.WriteLine("Podaj minimalna dlugosc tekstu:");
                    int minLen = int.Parse(Console.ReadLine());

                    Console.WriteLine("Podaj maksymalna dlugosc tekstu:");
                    int maxLen = int.Parse(Console.ReadLine());

                    GetProcessorTimes(out userStart, out kernelStart);
                    GetProcessMemoryInfoWrapper(Process.GetCurrentProcess().Handle, out pmcStart, (uint)Marshal.SizeOf<PROCESS_MEMORY_COUNTERS>());
                    stopwatch.Start();

                    for (int i = 0; i < ilosc; i++)
                    {
                        string text = GenerateRandomText(minLen, maxLen);
                        EncryptDecryptRSA(text, keySize);
                    }

                    stopwatch.Stop();
                    GetProcessorTimes(out userEnd, out kernelEnd);
                    GetProcessMemoryInfoWrapper(Process.GetCurrentProcess().Handle, out pmcEnd, (uint)Marshal.SizeOf<PROCESS_MEMORY_COUNTERS>());

                    double userTime = FileTimeToSeconds(userEnd) - FileTimeToSeconds(userStart);
                    double kernelTime = FileTimeToSeconds(kernelEnd) - FileTimeToSeconds(kernelStart);
                    double cpuUsage = (userTime + kernelTime) / stopwatch.Elapsed.TotalSeconds * 100;

                    Console.WriteLine("\n=== Statystyki wydajnosci ===");
                    Console.WriteLine($"Calkowity czas: {stopwatch.Elapsed.TotalSeconds} sekund");
                    PrintResourceUsage(cpuUsage, pmcEnd);
                }
            }
            else if (choice == "AES" || choice == "A")
            {
                Console.WriteLine("Czy chcesz podac wlasny tekst? (T/N)");
                char yn = Console.ReadKey().KeyChar;
                Console.WriteLine();

                FILETIME userStart, kernelStart, userEnd, kernelEnd;
                PROCESS_MEMORY_COUNTERS pmcStart, pmcEnd;
                Stopwatch stopwatch = new Stopwatch();

                if (yn == 'T' || yn == 't')
                {
                    Console.WriteLine("Podaj tekst:");
                    string plaintext = Console.ReadLine();

                    Console.WriteLine("Podaj rozmiar klucza 128, 192 lub 256: ");
                    int keySize = int.Parse(Console.ReadLine());

                    GetProcessorTimes(out userStart, out kernelStart);
                    GetProcessMemoryInfoWrapper(Process.GetCurrentProcess().Handle, out pmcStart, (uint)Marshal.SizeOf<PROCESS_MEMORY_COUNTERS>());
                    stopwatch.Start();

                    EncryptDecryptAES(plaintext, keySize);

                    stopwatch.Stop();
                    GetProcessorTimes(out userEnd, out kernelEnd);
                    GetProcessMemoryInfoWrapper(Process.GetCurrentProcess().Handle, out pmcEnd, (uint)Marshal.SizeOf<PROCESS_MEMORY_COUNTERS>());

                    double userTime = FileTimeToSeconds(userEnd) - FileTimeToSeconds(userStart);
                    double kernelTime = FileTimeToSeconds(kernelEnd) - FileTimeToSeconds(kernelStart);
                    double cpuUsage = (userTime + kernelTime) / stopwatch.Elapsed.TotalSeconds * 100;

                    Console.WriteLine("\n=== Statystyki wydajnosci ===");
                    Console.WriteLine($"Czas wykonania: {stopwatch.Elapsed.TotalSeconds} sekund");
                    PrintResourceUsage(cpuUsage, pmcEnd);
                }
                else
                {
                    Console.WriteLine("Podaj ilosc hasel:");
                    int ilosc = int.Parse(Console.ReadLine());

                    Console.WriteLine("Podaj rozmiar klucza 128, 192 lub 256: ");
                    int keySize = int.Parse(Console.ReadLine());

                    Console.WriteLine("Podaj minimalna dlugosc tekstu:");
                    int minLen = int.Parse(Console.ReadLine());

                    Console.WriteLine("Podaj maksymalna dlugosc tekstu:");
                    int maxLen = int.Parse(Console.ReadLine());

                    GetProcessorTimes(out userStart, out kernelStart);
                    GetProcessMemoryInfoWrapper(Process.GetCurrentProcess().Handle, out pmcStart, (uint)Marshal.SizeOf<PROCESS_MEMORY_COUNTERS>());
                    stopwatch.Start();

                    for (int i = 0; i < ilosc; i++)
                    {
                        string text = GenerateRandomText(minLen, maxLen);
                        EncryptDecryptAES(text, keySize);
                    }

                    stopwatch.Stop();
                    GetProcessorTimes(out userEnd, out kernelEnd);
                    GetProcessMemoryInfoWrapper(Process.GetCurrentProcess().Handle, out pmcEnd, (uint)Marshal.SizeOf<PROCESS_MEMORY_COUNTERS>());

                    double userTime = FileTimeToSeconds(userEnd) - FileTimeToSeconds(userStart);
                    double kernelTime = FileTimeToSeconds(kernelEnd) - FileTimeToSeconds(kernelStart);
                    double cpuUsage = (userTime + kernelTime) / stopwatch.Elapsed.TotalSeconds * 100;

                    Console.WriteLine("\n=== Statystyki wydajnosci ===");
                    Console.WriteLine($"Calkowity czas: {stopwatch.Elapsed.TotalSeconds} sekund");
                    PrintResourceUsage(cpuUsage, pmcEnd);
                }
            }
            else
            {
                Console.WriteLine("Nieprawidlowy wybor szyfrowania!");
            }
        }
    }
}