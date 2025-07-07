using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;


namespace RSA_LICZENIE_SLOW_C_ // Poprawiona nazwa przestrzeni
{
    public class LiczenieSlow
    {
        // Stałe kontrolujące pracę programu
        private static readonly int ROZMIAR_FRAGMENTU = 2 * 1024 * 1024; // 2MB
        private static readonly int OVERLAP_SIZE = 256;

        // Struktura przechowująca preprocesowane informacje dla algorytmu KMP
        private class KMP_Preprocessed
        {
            public List<int> lps;    // Tablica najdłuższych prefiksów-sufiksów
            public string pattern;   // Szukany wzorzec
        }

        // Struktura przechowująca metryki
        public struct Metrics
        {
            public int count;
            public double czas;
            public double cpu_usage;
            public long ram_usage;
        }

        // Funkcje pomocnicze do monitorowania zasobów
        private static TimeSpan GetCpuTime()
        {
            return Process.GetCurrentProcess().TotalProcessorTime;
        }

        // Zmiana metody pomiaru pamięci
        private static long GetMemoryUsage()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            return Process.GetCurrentProcess().WorkingSet64;
        }


        // Funkcje pomocnicze do przetwarzania plików
        private static string OdczytajCalyPlik(string sciezka)
        {
            return File.ReadAllText(sciezka, Encoding.UTF8);
        }

        private static List<Tuple<int, int>> PodzielNaFragmenty(string buffer)
        {
            List<Tuple<int, int>> fragmenty = new List<Tuple<int, int>>();
            int poz = 0;
            int bufferLength = buffer.Length;

            while (poz < bufferLength)
            {
                int start = (poz > OVERLAP_SIZE) ? (poz - OVERLAP_SIZE) : 0;
                int end = Math.Min(poz + ROZMIAR_FRAGMENTU, bufferLength);
                fragmenty.Add(Tuple.Create(start, end - start));
                poz = end;
            }
            return fragmenty;
        }

        // Implementacja algorytmu KMP
        private static KMP_Preprocessed PrzygotujWzorzec(string slowo)
        {
            KMP_Preprocessed result = new KMP_Preprocessed();
            result.pattern = slowo;
            int m = slowo.Length;
            result.lps = new List<int>(new int[m]);

            int len = 0;
            for (int i = 1; i < m;)
            {
                if (slowo[i] == slowo[len])
                {
                    len++;
                    result.lps[i] = len;
                    i++;
                }
                else
                {
                    if (len != 0)
                    {
                        len = result.lps[len - 1];
                    }
                    else
                    {
                        result.lps[i] = 0;
                        i++;
                    }
                }
            }
            return result;
        }

        private static int LiczbaSlowWeFragmencie(string buffer, int start, int length, KMP_Preprocessed wzorzec)
        {
            if (string.IsNullOrEmpty(wzorzec.pattern)) return 0;

            int count = 0;
            int end = start + length;
            int j = 0;

            for (int i = start; i < end;)
            {
                if (wzorzec.pattern[j] == buffer[i])
                {
                    j++;
                    i++;
                }

                if (j == wzorzec.pattern.Length)
                {
                    count++;
                    j = wzorzec.lps[j - 1];
                }
                else if (i < end && wzorzec.pattern[j] != buffer[i])
                {
                    if (j != 0) j = wzorzec.lps[j - 1];
                    else i++;
                }
            }
            return count;
        }

        // Wersja sekwencyjna
        public static Metrics LiczbaSlowSekwencyjny(string sciezkaPliku, string slowo)
        {
            var startCpu = GetCpuTime();
            var startTime = DateTime.Now;
            long startMem = GetMemoryUsage();

            string buffer = OdczytajCalyPlik(sciezkaPliku);
            var fragmenty = PodzielNaFragmenty(buffer);
            var wzorzec = PrzygotujWzorzec(slowo);

            int total = 0;
            foreach (var fragment in fragmenty)
            {
                total += LiczbaSlowWeFragmencie(buffer, fragment.Item1, fragment.Item2, wzorzec);
            }

            var endTime = DateTime.Now;
            var endCpu = GetCpuTime();
            long endMem = GetMemoryUsage();

            return ObliczMetryki(startTime, endTime, startCpu, endCpu, startMem, endMem, total);
        }

        // Wersja z użyciem wątków
        public static Metrics LiczbaSlowThread(string sciezkaPliku, string slowo, int liczbaWatkow)
        {
            var startCpu = GetCpuTime();
            var startTime = DateTime.Now;
            long startMem = GetMemoryUsage();

            string buffer = OdczytajCalyPlik(sciezkaPliku);
            var fragmenty = PodzielNaFragmenty(buffer);
            var wzorzec = PrzygotujWzorzec(slowo);

            int total = 0;
            object lockObj = new object();
            int fragPerWatek = (fragmenty.Count + liczbaWatkow - 1) / liczbaWatkow;

            List<Thread> watki = new List<Thread>();
            for (int i = 0; i < liczbaWatkow; i++)
            {
                int threadId = i;
                Thread watek = new Thread(() =>
                {
                    int localCount = 0;
                    int start = threadId * fragPerWatek;
                    int end = Math.Min(start + fragPerWatek, fragmenty.Count);

                    for (int j = start; j < end; j++)
                    {
                        var fragment = fragmenty[j];
                        localCount += LiczbaSlowWeFragmencie(buffer, fragment.Item1, fragment.Item2, wzorzec);
                    }

                    lock (lockObj) total += localCount;
                });
                watki.Add(watek);
                watek.Start();
            }

            foreach (var watek in watki) watek.Join();

            var endTime = DateTime.Now;
            var endCpu = GetCpuTime();
            long endMem = GetMemoryUsage();

            return ObliczMetryki(startTime, endTime, startCpu, endCpu, startMem, endMem, total);
        }

        // Wersja z użyciem OpenMP
        public static Metrics LiczbaSlowParallel(string sciezkaPliku, string slowo, int liczbaWatkow)
        {
            var startCpu = GetCpuTime();
            var startTime = DateTime.Now;
            long startMem = GetMemoryUsage();

            string buffer = OdczytajCalyPlik(sciezkaPliku);
            var fragmenty = PodzielNaFragmenty(buffer);
            var wzorzec = PrzygotujWzorzec(slowo);

            int total = 0;
            Parallel.For(0, fragmenty.Count, new ParallelOptions { MaxDegreeOfParallelism = liczbaWatkow },
                () => 0,
                (i, state, localTotal) =>
                {
                    var fragment = fragmenty[i];
                    return localTotal + LiczbaSlowWeFragmencie(buffer, fragment.Item1, fragment.Item2, wzorzec);
                },
                localTotal => Interlocked.Add(ref total, localTotal));

            var endTime = DateTime.Now;
            var endCpu = GetCpuTime();
            long endMem = GetMemoryUsage();

            return ObliczMetryki(startTime, endTime, startCpu, endCpu, startMem, endMem, total);
        }

        private static Metrics ObliczMetryki(DateTime startTime, DateTime endTime, TimeSpan startCpu, TimeSpan endCpu, long startMem, long endMem, int total)
        {
            double czas = (endTime - startTime).TotalSeconds;
            double cpuTime = (endCpu - startCpu).TotalSeconds;
            int numCpus = Environment.ProcessorCount;
            double cpuUsage = (cpuTime / (czas * numCpus)) * 100;
            long ramUsage = Math.Max(0, endMem - startMem);

            return new Metrics
            {
                count = total,
                czas = czas,
                cpu_usage = cpuUsage,
                ram_usage = ramUsage
            };
        }

        // Główna funkcja interfejsu użytkownika
        public static void Liczenie_Slow()
        {
            // Ustawienie kodowania konsoli na UTF-8
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            Console.Write("Podaj nazwe uzytkownika: ");
            string user = Console.ReadLine();

            Console.Write("Podaj ilosc watkow: ");
            int watki = int.Parse(Console.ReadLine());

            Console.Write("Podaj ilosc slow: ");
            int n = int.Parse(Console.ReadLine());

            List<string> slowa = new List<string>();
            for (int i = 0; i < n; i++)
            {
                Console.Write($"Podaj {i + 1}. slowo: ");
                slowa.Add(Console.ReadLine());
            }

            Console.Write("Podaj nazwe pliku: ");
            string plik = Console.ReadLine();
            string sciezka = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), plik);

            int totalSek = 0, totalThr = 0, totalParal = 0;
            double czasSek = 0, czasThr = 0, czasParal = 0;
            double cpuSek = 0, cpuThr = 0, cpuParal = 0;
            long ramSek = 0, ramThr = 0, ramParal = 0;

            foreach (var slowo in slowa)
            {
                var sek = LiczbaSlowSekwencyjny(sciezka, slowo);
                var thr = LiczbaSlowThread(sciezka, slowo, watki);
                var paral = LiczbaSlowParallel(sciezka, slowo, watki);

                Console.WriteLine($"\nSlowo: {slowo}");
                Console.WriteLine($"Sekwencyjnie: {sek.count} (czas: {sek.czas:F2}s, CPU: {sek.cpu_usage:F1}%, RAM: {sek.ram_usage} B)");
                Console.WriteLine($"Threading: {thr.count} (czas: {thr.czas:F2}s, CPU: {thr.cpu_usage:F1}%, RAM: {thr.ram_usage} B)");
                Console.WriteLine($"Parallel: {paral.count} (czas: {paral.czas:F2}s, CPU: {paral.cpu_usage:F1}%, RAM: {paral.ram_usage} B)\n");

                totalSek += sek.count;
                totalThr += thr.count;
                totalParal += paral.count;

                czasSek += sek.czas;
                czasThr += thr.czas;
                czasParal += paral.czas;

                cpuSek += sek.cpu_usage;
                cpuThr += thr.cpu_usage;
                cpuParal += paral.cpu_usage;

                ramSek += sek.ram_usage;
                ramThr += thr.ram_usage;
                ramParal += paral.ram_usage;
            }

            Console.WriteLine("\nPodsumowanie:");
            Console.WriteLine($"Sekwencyjnie: {totalSek} (czas: {czasSek:F2}s, CPU: {cpuSek / slowa.Count:F1}%, RAM: {ramSek} B)");
            Console.WriteLine($"Threading: {totalThr} (czas: {czasThr:F2}s, CPU: {cpuThr / slowa.Count:F1}%, RAM: {ramThr} B)");
            Console.WriteLine($"Parallel: {totalParal} (czas: {czasParal:F2}s, CPU: {cpuParal / slowa.Count:F1}%, RAM: {ramParal} B)");
        }
    }
}