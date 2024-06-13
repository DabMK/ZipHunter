using Ionic.Zip;
using Ionic.Zlib;
using System.Diagnostics;

#pragma warning disable IDE0063
namespace ZipHunter
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            // Check arguments
            if (args.Length < 2 || string.IsNullOrWhiteSpace(args[0]) || !args[0].Contains('.') || !args[0].Contains('\\') || string.IsNullOrWhiteSpace(args[1]))
            {
                Console.WriteLine("Usage: \"ZipHunter <zipPath> <wordList> <encryptionAlgorithm>\" (default value of <encryptionAlgorithm> is \"PkzipWeak\", to bruteforce type \"bruteforce\" as the <wordList>)");
                Environment.Exit(1);
            }
            string path = args[0];
            string wlPath = args[1];

            // Check file paths provided
            if (!File.Exists(path))
            {
                Console.WriteLine($"The zip path \"{path}\" couldn't be found on this system");
                Environment.Exit(1);
            }
            if ((!wlPath.Equals("bruteforce", StringComparison.OrdinalIgnoreCase) && !File.Exists(wlPath)) || new FileInfo(wlPath).Length < 1)
            {
                Console.WriteLine($"The word list path \"{wlPath}\" couldn't be found on this system. Remember to type \"bruteforce\" to bruteforce the zip file");
                Environment.Exit(1);
            }

            // Check if extraction path already exists
            string extPath = @$"{Path.GetDirectoryName(path)}\{Path.GetFileNameWithoutExtension(path)}\";
            while (Directory.Exists(extPath))
            {
                Random rnd = new();
                extPath = extPath.Remove(extPath.Length - 1);
                extPath += @$"{rnd.Next(10)}\";
            }
            Directory.CreateDirectory(extPath);

            ZipFile archive = new(path);
            SetEncryptionMethod(ref archive, args);

            // Fastest way to read wordlist I have found
            Stopwatch sw;
            using (StreamReader sr = File.OpenText(wlPath))
            {
                string s = string.Empty;
                int attempt = 1;
                while ((s = sr.ReadLine()) != null)
                {
                    sw = Stopwatch.StartNew();
                    // Check if password is correct
                    Console.Write($"Trying out password (Attempt {attempt}): \"{s}\"");
                    archive.Password = s;
                    try
                    {
                        archive.ExtractAll(extPath, ExtractExistingFileAction.Throw);
                        sw.Stop();
                        Console.WriteLine($"\n\nPASSWORD IS CORRECT! Extracted in {extPath}, taking away {sw.ElapsedMilliseconds}ms");
                        break;
                    }
                    catch (BadPasswordException)
                    {
                        Console.Write(Environment.NewLine);
                        attempt++;
                    }
                    catch (ZlibException ex)
                    {
                        Console.WriteLine($" - Error \"{ex.Message}\". Clearing cache and trying again...");
                        foreach (FileInfo file in new DirectoryInfo(extPath).GetFiles()) { file.Delete(); }
                        archive = new(path);
                        SetEncryptionMethod(ref archive, args);
                        attempt++;
                    }
                }
            }
        }

        private static void SetEncryptionMethod(ref ZipFile archive, string[] args)
        {
            archive.Encryption = EncryptionAlgorithm.PkzipWeak;
            if (args.Length > 2 && !string.IsNullOrWhiteSpace(args[2]))
            {
                string algorithm = args[2];
                switch (algorithm.ToLower())
                {
                    case "none":
                        archive.Encryption = EncryptionAlgorithm.None; break;
                    case "unsupported":
                        archive.Encryption = EncryptionAlgorithm.Unsupported; break;
                    case "128":
                    case "aes128":
                    case "winaes128":
                    case "zipaes128":
                    case "winzipaes128":
                        archive.Encryption = EncryptionAlgorithm.WinZipAes128; break;
                    case "256":
                    case "aes256":
                    case "winaes256":
                    case "zipaes256":
                    case "winzipaes256":
                        archive.Encryption = EncryptionAlgorithm.WinZipAes256; break;
                }
            }
        }
    }
}