using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

class DecryptClipboardLogs
{
    static void Main()
    {
        Console.Write("Enter the 32-byte Key (e.g. 12345678901234567890123456789012): ");
        string keyInput = Console.ReadLine();

        Console.Write("Enter the 16-byte IV (e.g. 1234567890123456): ");
        string ivInput = Console.ReadLine();

        if (keyInput == null || ivInput == null ||
            keyInput.Length != 32 || ivInput.Length != 16)
        {
            Console.WriteLine("Key must be exactly 32 characters and IV must be exactly 16 characters.");
            return;
        }

        byte[] key = Encoding.UTF8.GetBytes(keyInput);
        byte[] iv = Encoding.UTF8.GetBytes(ivInput);

        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "clipboard_log.txt");
        if (!File.Exists(path))
        {
            Console.WriteLine("Log file not found.");
            return;
        }

        foreach (string line in File.ReadAllLines(path))
        {
            try
            {
                string decrypted = Decrypt(line, key, iv);
                Console.WriteLine(decrypted);
            }
            catch
            {
                Console.WriteLine("[Could not decrypt line]");
            }
        }
    }

    static string Decrypt(string encryptedBase64, byte[] key, byte[] iv)
    {
        byte[] cipherText = Convert.FromBase64String(encryptedBase64);

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var decryptor = aes.CreateDecryptor())
            using (var ms = new MemoryStream(cipherText))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var sr = new StreamReader(cs))
            {
                return sr.ReadToEnd();
            }
        }
    }
}
