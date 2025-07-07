// Plik Program.cs
using RSA_LICZENIE_SLOW_C_; // Poprawiona nazwa przestrzeni
using System;

class Program
{
    static void Main()
    {
        Console.WriteLine("Wybierz opcje:");
        Console.WriteLine("1. Liczenie słów w pliku");
        Console.WriteLine("2. Szyfrowanie RSA/AES");

        if (int.TryParse(Console.ReadLine(), out int wybor))
        {
            if (wybor == 1)
            {
                LiczenieSlow.Liczenie_Slow();
            }
            else if (wybor == 2)
            {
                // Poprawne wywołanie przez instancję
                new Szyfrowanie().SzyfrowanieMetoda();
            }
            else
            {
                Console.WriteLine("Nieprawidłowy wybór.");
            }
        }
        else
        {
            Console.WriteLine("Błąd: Wprowadź liczbę.");
        }
    }
}