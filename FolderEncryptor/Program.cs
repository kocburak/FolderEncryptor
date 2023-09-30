using System.CommandLine;
using System.CommandLine.Parsing;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace FolderEncryptor
{
    internal class Program
    {
        static async Task<int> Main(string[] args)
        {
            var silentOption = new Option<bool>(
                aliases: new string[] { "--silent", "-s" },
                getDefaultValue: () => false,
                description: "Disable console output.")
            {
                Arity = ArgumentArity.Zero,
            };

            var encryptFileName = new Option<bool>(
                aliases: new string[] { "--enc-filenames", "-eF" },
                getDefaultValue: () => false,
                description: "Is filenames are encrypted.")
            {
                Arity = ArgumentArity.Zero,
            };

            var passwordOption = new Option<string?>(
                aliases: new string[] { "--password", "-p" },
                description: "Provide password as argument.")
            {
                Arity = ArgumentArity.ExactlyOne,
            };

            var directoryOption = new Option<DirectoryInfo>(
                aliases: new string[] { "--dir", "-d" },
                description: "The directory to be processed.")
            {
                Arity = ArgumentArity.ExactlyOne,
                IsRequired = true
            };

            var decryptionDestinationDirectoryOption = new Option<DirectoryInfo>(
                aliases: new string[] { "--desDir", "-dD" },
                getDefaultValue: () => new DirectoryInfo(Path.Combine(Directory.GetCurrentDirectory(), "decrypted")),
                description: "The destination directory of decrypted files.")
            {
                Arity = ArgumentArity.ExactlyOne,
            };

            var encryptionDestinationDirectoryOption = new Option<DirectoryInfo>(
                aliases: new string[] { "--desDir", "-dD" },
                getDefaultValue: () => new DirectoryInfo(Path.Combine(Directory.GetCurrentDirectory(), "encrypted")),
                description: "The destination directory of encrypted files.")
            {
                Arity = ArgumentArity.ExactlyOne,
            };

            var encryptCommand = new Command("enc", "Encrypt the spesified target.")
            {
                directoryOption,
                encryptionDestinationDirectoryOption,
                encryptFileName,
                passwordOption
            };

            encryptCommand.SetHandler((dir, desDir, argPassword, isSilent, isFileNameEncrypted) =>
            {
                StringBuilder password;
                if (string.IsNullOrWhiteSpace(argPassword))
                    password = ReadLine();
                else
                    password = new StringBuilder(argPassword);

                EncryptFolder(dir.FullName, desDir.FullName, password, isSilent, isFileNameEncrypted);
            }, directoryOption, encryptionDestinationDirectoryOption, passwordOption, silentOption, encryptFileName);

            var decryptCommand = new Command("dec", "Decrypt the spesified target.")
            {
                directoryOption,
                decryptionDestinationDirectoryOption,
                encryptFileName,
                passwordOption
            };

            decryptCommand.SetHandler((dir, desDir, argPassword, isSilent, isFileNameEncrypted) =>
            {
                StringBuilder password;
                if (string.IsNullOrWhiteSpace(argPassword))
                    password = ReadLine();
                else
                    password = new StringBuilder(argPassword);

                DecryptFolder(dir.FullName, desDir.FullName, password, isSilent, isFileNameEncrypted);
            }, directoryOption, decryptionDestinationDirectoryOption, passwordOption, silentOption, encryptFileName);

            var analyzeCommand = new Command("analyze", "Analyze the spesified target.")
            {
                directoryOption,
            };
            analyzeCommand.SetHandler((dir) =>
            {
                List<string> files = Directory.GetFiles(dir.FullName).ToList();
                GetSubDirectories(dir.FullName, files);

                Console.WriteLine("Total number of files: " + files.Count);
            }, directoryOption);

            var rootCommand = new RootCommand("Directory encryption tool.");

            rootCommand.AddGlobalOption(silentOption);

            rootCommand.AddCommand(encryptCommand);
            rootCommand.AddCommand(decryptCommand);
            rootCommand.AddCommand(analyzeCommand);

            return await rootCommand.InvokeAsync(args);
        }

        private static StringBuilder ReadLine()
        {
            Console.Write("Enter passphrase: ");
            var password = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Remove(password.Length - 1, 1);
                        //Console.Write("\b \b");
                    }
                }
                else if (key.KeyChar != '\u0000') // KeyChar == '\u0000' if the key pressed does not correspond to a printable character, e.g. F1, Pause-Break, etc
                {
                    password.Append(key.KeyChar);
                    //Console.Write("*");
                }
            }
            Console.WriteLine();
            return password;
        }

        private static void SetAESParameters([NotNull] StringBuilder password, [NotNull] Aes aes, byte[] salt)
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(password.ToString(), salt, 1000).GetBytes(32);
            aes.Key = key;
            aes.IV = new byte[16];
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
        }

        static void GetSubDirectories(string sourceFolder, List<string> files)
        {
            var dirs = Directory.GetDirectories(sourceFolder);

            foreach (var subDirs in dirs)
            {
                files.AddRange(Directory.GetFiles(subDirs).ToList());
                GetSubDirectories(subDirs, files);
            }
        }

        private static string EncryptFilePath(string relativeFilePath, Aes aes)
        {
            string result;
            var encryptor = aes.CreateEncryptor();

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(relativeFilePath);
                    }
                }
                result = Convert.ToBase64String(ms.ToArray()).Replace("/", "_");
            }
            return result;
        }

        private static string DecryptFilePath(string encryptedFilePath, Aes aes)
        {
            var decryptor = aes.CreateDecryptor();
            var qwe = encryptedFilePath.Replace("_", "/");
            var cipherText = Convert.FromBase64String(qwe);
            string result;
            using (MemoryStream ms = new MemoryStream(cipherText))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(cs))
                        result = reader.ReadToEnd();

                }
            }
            Console.WriteLine(result);
            return result;
        }

        private static void EncryptFolder(string sourceFolder, string destinationFolder, StringBuilder password, bool isSilent, bool encryptFileName)
        {

            var totalTimer = new Stopwatch();
            if (!isSilent)
                totalTimer.Start();

            // Generate a random salt value
            // Encrypt each file in the source folder and copy it to the destination folder
            List<string> files = Directory.GetFiles(sourceFolder).ToList();
            GetSubDirectories(sourceFolder, files);

            object lockObj = new object();

            Parallel.ForEach(files, (filePath) =>
            //foreach (string filePath in files)
            {
                if (!isSilent)
                    Console.WriteLine("Encryption started for: " + filePath);

                var fileTimer = Stopwatch.StartNew();

                var relativeFilePath = filePath.Replace(sourceFolder + Path.DirectorySeparatorChar, "");

                using (var rng = RandomNumberGenerator.Create())
                {
                    byte[] salt = new byte[8];
                    rng.GetBytes(salt);

                    if (encryptFileName)
                    {
                        using (var aes = Aes.Create())
                        {
                            SetAESParameters(password, aes, salt);
                            relativeFilePath = EncryptFilePath(relativeFilePath, aes);
                        }
                    }

                    var destination = Path.Combine(destinationFolder, relativeFilePath);
                    var finalDestinationFolder = Path.GetDirectoryName(destination);

                    lock (lockObj)
                    {
                        // Create the destination folder if it doesn't exist
                        if (!Directory.Exists(finalDestinationFolder))
                            Directory.CreateDirectory(finalDestinationFolder);

                    }

                    using (var fsIn = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (var fsOut = new FileStream(destination, FileMode.Create, FileAccess.Write))
                    using (var aes = Aes.Create())
                    {
                        SetAESParameters(password, aes, salt);

                        // Write the salt value to the beginning of the output file
                        fsOut.Write(salt, 0, salt.Length);

                        // Encrypt the file using the AES algorithm
                        using (var cryptoStream = new CryptoStream(fsOut, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            fsIn.CopyTo(cryptoStream);
                        }
                    }

                }

                if (!isSilent)
                {
                    fileTimer.Stop();
                    Console.WriteLine("Encryption finished. Time taken: " + fileTimer.Elapsed.ToString(@"m\:ss\.fff") + " for: " + filePath);
                }
            });

            if (!isSilent)
            {
                totalTimer.Stop();
                TimeSpan timeTaken = totalTimer.Elapsed;
                Console.WriteLine();
                Console.WriteLine("Total time taken: " + timeTaken.ToString(@"m\:ss\.fff"));
            }

        }

        private static void DecryptFolder(string sourceFolder, string destinationFolder, StringBuilder password, bool isSilent, bool decryptFileName)
        {
            var totalTimer = new Stopwatch();

            if (!isSilent)
                totalTimer.Start();

            // Loop through each file in the source folder
            List<string> files = Directory.GetFiles(sourceFolder).ToList();
            GetSubDirectories(sourceFolder, files);

            object lockObj = new object();

            Parallel.ForEach(files, (filePath) =>
            //foreach (string filePath in files)
            {

                if (!isSilent)
                    Console.WriteLine("Decryption started for: " + filePath);

                var fileTimer = Stopwatch.StartNew();

                using (var fsIn = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    // Read the salt value from the beginning of the input file
                    byte[] salt = new byte[8];
                    fsIn.Read(salt, 0, salt.Length);

                    var relativeFilePath = filePath.Replace(sourceFolder + Path.DirectorySeparatorChar, "");
                    Console.WriteLine(relativeFilePath);

                    if (decryptFileName)
                    {
                        using (var aes = Aes.Create())
                        {
                            SetAESParameters(password, aes, salt);
                            relativeFilePath = DecryptFilePath(relativeFilePath, aes);
                        }
                        Console.WriteLine(relativeFilePath);
                    }

                    var destination = Path.Combine(destinationFolder, relativeFilePath);
                    var finalDestinationFolder = Path.GetDirectoryName(destination);
                    // Create the destination folder if it doesn't exist
                    lock (lockObj)
                    {
                        if (!Directory.Exists(finalDestinationFolder))
                            Directory.CreateDirectory(finalDestinationFolder);
                    }

                    using (var aes = Aes.Create())
                    {
                        SetAESParameters(password, aes, salt);
                        using (var cryptoStream = new CryptoStream(fsIn, aes.CreateDecryptor(), CryptoStreamMode.Read))
                        using (var fsOut = new FileStream(destination, FileMode.Create, FileAccess.Write))

                        {
                            cryptoStream.CopyTo(fsOut);
                        }
                    }
                }
                if (!isSilent)
                {
                    fileTimer.Stop();
                    Console.WriteLine("Decryption finished. Time taken: " + fileTimer.Elapsed.ToString(@"m\:ss\.fff") + " for: " + filePath);
                }

            });
            if (!isSilent)
            {
                totalTimer.Stop();
                TimeSpan timeTaken = totalTimer.Elapsed;
                Console.WriteLine();
                Console.WriteLine("Total time taken: " + timeTaken.ToString(@"m\:ss\.fff"));
            }
        }
    }

}