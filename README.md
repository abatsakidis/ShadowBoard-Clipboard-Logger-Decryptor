# ShadowBoard Clipboard Logger & Decryptor

This program monitors the system clipboard for sensitive information such as passwords, tokens, API keys, and other patterns. It encrypts detected data using AES encryption and stores it securely in a local log file. A complementary decryptor tool allows authorized users to decrypt and review the logged data. Designed for security auditing and educational purposes.

## Overview

This project consists of two C# console applications:

1. **ShadowBoard Clipboard Logger**  
   Continuously monitors the Windows clipboard for text entries matching sensitive data patterns (e.g., passwords, tokens, API keys).  
   When such data is detected, it encrypts the information using AES-256-CBC and logs it securely to a file.  
   It also includes a "Kill Switch" feature to gracefully terminate the program when a special command is detected in any open `cmd` window title.

2. **DecryptClipboardLogs**  
   A simple tool to decrypt the encrypted clipboard logs created by the Clipboard Logger.  
   It prompts the user to enter the AES key and IV to decrypt the stored logs and display the original sensitive information.

---

## Features

### Clipboard Logger

- Monitors clipboard changes in real-time.
- Detects sensitive data based on customizable regex patterns, including passwords, tokens, API keys, URLs, emails, credit card numbers, IBANs, JWT tokens, and more.
- Encrypts all detected sensitive data using AES-256-CBC with PKCS7 padding.
- Logs encrypted entries to a file at:  
  `%LocalAppData%\clipboard_log.txt`
- Implements a Kill Switch by monitoring open CMD windows for the title containing `!exit`, allowing graceful shutdown.
- Automatically hides its console window on start.
- Adds itself to Windows startup registry for persistence.

### DecryptClipboardLogs

- Reads the encrypted log file from `%LocalAppData%\clipboard_log.txt`.
- Requests the AES key and IV from the user on startup (no hardcoded keys).
- Decrypts each log entry and prints the plaintext content.
- Handles decryption errors gracefully.

---

## Usage

### Clipboard Logger

1. Compile `Program.cs` into an executable.
2. Run the executable — it will run hidden and start monitoring your clipboard.
3. To stop the logger, open any command prompt window and rename its title to include `!exit`, or terminate the process manually.

### DecryptClipboardLogs

1. Compile `DecryptClipboardLogs.cs` into an executable.
2. Run the executable.
3. When prompted, enter the AES key (32 bytes) and IV (16 bytes) exactly as used by the logger.
4. The program will decrypt and print all the stored clipboard entries line by line.

---

## Notes

- Ensure that the AES key and IV match exactly between the logger and decryptor.
- The regex patterns can be customized in the Clipboard Logger source code to suit your detection needs.
- The logger only captures clipboard text; it does **not** intercept keystrokes or browser stored passwords.
- Use responsibly and respect privacy and legal regulations.

---

## Example AES Key and IV

For testing, the logger uses:

```csharp
byte[] key = Encoding.UTF8.GetBytes("12345678901234567890123456789012"); // 32 bytes
byte[] iv = Encoding.UTF8.GetBytes("1234567890123456"); // 16 bytes
```

## License

This project is provided as-is without warranty. Use at your own risk.

## Disclaimer

This software is intended **for educational purposes only**.  
The author assumes no responsibility or liability for any misuse or illegal activities conducted using this software.  
Use it responsibly and ethically.