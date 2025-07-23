using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using OfficeOpenXml;

class PermissionAuditTool
{
    static string username = null;
    static string password = null;
    static bool isAuthenticated = false;

    static void Main(string[] args)
    {
        if (args.Length == 1 && args[0].Equals("/?", StringComparison.OrdinalIgnoreCase))
        {
            ShowHelp();
            return;
        }

        bool recursiveScan = false;
        bool mergeResults = false;
        bool sharedOnly = false;
        bool smbSharesOnly = false;
        string serverName = null;
        List<string> directoriesToScan = new List<string>();
        string logFilePath = "ErrorLog.txt";

        // Парсинг аргументов
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLower())
            {
                case "-recursive":
                    recursiveScan = true;
                    break;
                case "-merge":
                    mergeResults = true;
                    break;
                case "-sharedonly":
                    sharedOnly = true;
                    break;
                case "-smbsharesonly":
                    smbSharesOnly = true;
                    if (i + 1 < args.Length)
                    {
                        serverName = args[++i];
                    }
                    else
                    {
                        Console.WriteLine("Error: -smbsharesonly requires a server name.");
                        return;
                    }
                    break;
                case "-username":
                    if (i + 1 < args.Length)
                    {
                        username = args[++i];
                    }
                    else
                    {
                        Console.WriteLine("Error: -username requires a value.");
                        return;
                    }
                    break;
                case "-file":
                    if (i + 1 < args.Length && File.Exists(args[i + 1]))
                    {
                        directoriesToScan.AddRange(File.ReadLines(args[i + 1])
                            .Where(line => !string.IsNullOrWhiteSpace(line)));
                        i++;
                    }
                    else
                    {
                        Console.WriteLine("Invalid file path provided.");
                        return;
                    }
                    break;
                default:
                    if (Directory.Exists(args[i]) || IsUncPath(args[i]))
                    {
                        directoriesToScan.Add(args[i]);
                    }
                    else
                    {
                        LogError(args[i], logFilePath);
                    }
                    break;
            }
        }

        if (smbSharesOnly && string.IsNullOrWhiteSpace(serverName))
        {
            Console.WriteLine("Error: -smbsharesonly requires a server name.");
            return;
        }

        if (!smbSharesOnly && directoriesToScan.Count == 0)
        {
            Console.WriteLine("No valid directories to scan. Use /? for help.");
            return;
        }

        // Запрос пароля, если указан username
        if (!string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password))
        {
            Console.Write("Enter password for user '" + username + "': ");
            password = ReadPassword();
            Console.WriteLine();
        }

        List<string> finalDirectories = new List<string>();

        try
        {
            // Аутентификация через net use
            if (!string.IsNullOrEmpty(username))
            {
                if (!ConnectToServer(username, password, serverName))
                {
                    Console.WriteLine("Failed to authenticate. Check username and password.");
                    return;
                }
                isAuthenticated = true;
            }

            if (smbSharesOnly)
            {
                var shares = GetSmbSharesFromServer(serverName);
                finalDirectories.AddRange(shares);
            }
            else
            {
                foreach (string path in directoriesToScan)
                {
                    if (sharedOnly)
                    {
                        var sharedPaths = GetSharedFoldersViaNetShare();
                        finalDirectories.AddRange(sharedPaths.Where(p => IsSubPath(p, path)));
                        if (recursiveScan)
                        {
                            finalDirectories.AddRange(sharedPaths.Where(p => p.StartsWith(path, StringComparison.OrdinalIgnoreCase)));
                        }
                    }
                    else
                    {
                        finalDirectories.Add(path);
                        if (recursiveScan && Directory.Exists(path))
                        {
                            finalDirectories.AddRange(Directory.GetDirectories(path, "*", SearchOption.AllDirectories));
                        }
                    }
                }
            }

            finalDirectories = finalDirectories.Distinct().OrderBy(d => d).ToList();

            if (finalDirectories.Count == 0)
            {
                Console.WriteLine("No directories to scan after filtering.");
                return;
            }

            string reportFileName = null;

            if (mergeResults)
            {
                reportFileName = GenerateMergedAccessReport(finalDirectories);
            }
            else
            {
                foreach (string dir in finalDirectories)
                {
                    reportFileName = GenerateAccessReport(dir);
                }
            }

            // Открыть отчёт
            if (!string.IsNullOrEmpty(reportFileName) && File.Exists(reportFileName))
            {
                Process.Start(new ProcessStartInfo(reportFileName) { UseShellExecute = true });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
        finally
        {
            // Отключение
            if (isAuthenticated)
            {
                DisconnectAll();
            }
        }

        if (File.Exists(logFilePath) && new FileInfo(logFilePath).Length > 0)
        {
            Console.WriteLine($"Errors logged to '{logFilePath}'.");
        }
    }

    static string ReadPassword()
    {
        string password = "";
        ConsoleKey key;
        do
        {
            var keyInfo = Console.ReadKey(intercept: true);
            key = keyInfo.Key;
            if (key == ConsoleKey.Backspace && password.Length > 0)
            {
                Console.Write("\b \b");
                password = password.Substring(0, password.Length - 1);
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
                Console.Write("*");
                password += keyInfo.KeyChar;
            }
        } while (key != ConsoleKey.Enter);
        return password;
    }

    static bool ConnectToServer(string username, string password, string serverName)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "net",
                Arguments = $"use \\\\{serverName}\\IPC$ /user:{username} \"{password}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (var process = Process.Start(startInfo))
            {
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                return process.ExitCode == 0;
            }
        }
        catch
        {
            return false;
        }
    }

    static void DisconnectAll()
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "net",
                Arguments = "use * /delete /y",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            Process.Start(startInfo)?.WaitForExit();
        }
        catch { }
    }

    static List<string> GetSmbSharesFromServer(string server)
    {
        var shares = new List<string>();

        // Определяем, является ли сервер локальным
        bool isLocalServer = IsLocalMachine(server);

        if (isLocalServer)
        {
            // Используем локальный net share
            shares = GetSharedFoldersViaNetShare();
        }
        else
        {
            // Используем удалённый PowerShell
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"Get-CimInstance -ComputerName {server} -Class Win32_Share -ErrorAction Stop | Where-Object {{ $_.Type -eq 0 }} | Select-Object -ExpandProperty Path\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(startInfo))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode == 0)
                    {
                        foreach (string line in output.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            string path = line.Trim();
                            if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                            {
                                shares.Add(path);
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Failed to retrieve shares from {server} via PowerShell.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving shares from {server}: {ex.Message}");
            }
        }

        return shares;
    }

    static bool IsLocalMachine(string serverNameOrIp)
    {
        try
        {
            // Получаем локальные имена
            string hostName = Environment.MachineName;
            string fqdn = $"{hostName}.{Environment.GetEnvironmentVariable("USERDNSDOMAIN") ?? ""}".TrimEnd('.');
            string localhostNames = "localhost,127.0.0.1,::1,.";

            // Получаем локальные IP-адреса
            var localIps = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName())
                .AddressList
                .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                .Select(ip => ip.ToString());

            // Проверяем совпадение
            return string.Equals(serverNameOrIp, hostName, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(serverNameOrIp, fqdn, StringComparison.OrdinalIgnoreCase) ||
                   localhostNames.Split(',').Contains(serverNameOrIp, StringComparer.OrdinalIgnoreCase) ||
                   localIps.Contains(serverNameOrIp);
        }
        catch
        {
            return false;
        }
    }

    static List<string> GetSharedFoldersViaNetShare()
    {
        var sharedPaths = new List<string>();
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "net",
                Arguments = "share",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Environment.SystemDirectory
            };

            using (var process = Process.Start(startInfo))
            {
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                string[] lines = output.Split(new[] { Environment.NewLine }, StringSplitOptions.None);

                foreach (string line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line) ||
                        line.Contains("Share name", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("The command completed successfully", StringComparison.OrdinalIgnoreCase))
                        continue;

                    int pathStartIndex = -1;
                    for (int i = 0; i < line.Length - 2; i++)
                    {
                        if (char.IsLetter(line[i]) && line[i + 1] == ':' && (line[i + 2] == '\\' || line[i + 2] == '/'))
                        {
                            pathStartIndex = i;
                            break;
                        }
                    }

                    if (pathStartIndex != -1)
                    {
                        string path = line.Substring(pathStartIndex).Trim();
                        if (Directory.Exists(path))
                        {
                            sharedPaths.Add(Path.GetFullPath(path));
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to retrieve shares via 'net share': {ex.Message}");
        }
        return sharedPaths.Distinct().ToList();
    }

    static bool IsUncPath(string path)
    {
        return !string.IsNullOrEmpty(path) && path.StartsWith("\\\\", StringComparison.OrdinalIgnoreCase);
    }

    static bool IsSubPath(string child, string parent)
    {
        try
        {
            var parentUri = new Uri(Path.GetFullPath(parent) + Path.DirectorySeparatorChar);
            var childUri = new Uri(Path.GetFullPath(child) + Path.DirectorySeparatorChar);
            return childUri.IsBaseOf(parentUri);
        }
        catch
        {
            return false;
        }
    }

    static string GenerateAccessReport(string directoryPath)
    {
        string fileName = Path.GetFileName(directoryPath);
        string reportFileName = $"AccessReport_{DateTime.Now:yyyy.MM.dd.HHmmss}_{fileName}.xlsx";

        using (var package = new ExcelPackage(new FileInfo(reportFileName)))
        {
            string worksheetName = Path.GetFileName(directoryPath);
            if (worksheetName.Length > 31) worksheetName = worksheetName.Substring(0, 31);
            worksheetName = string.Join("_", worksheetName.Split(Path.GetInvalidFileNameChars()));

            var worksheet = package.Workbook.Worksheets.Add(worksheetName);
            PopulateHeaders(worksheet);
            int row = 2;

            ProcessDirectories(new[] { directoryPath }, worksheet, ref row);

            for (int i = 1; i <= 9; i++)
            {
                worksheet.Column(i).AutoFit();
            }

            package.Save();
        }

        Console.WriteLine($"Report saved to {reportFileName}");
        return reportFileName;
    }

    static string GenerateMergedAccessReport(List<string> directoriesToScan)
    {
        string reportFileName = $"AccessReport_Merged_{DateTime.Now:yyyy.MM.dd.HHmmss}.xlsx";

        using (var package = new ExcelPackage(new FileInfo(reportFileName)))
        {
            var worksheet = package.Workbook.Worksheets.Add("Merged Access Report");
            PopulateHeaders(worksheet);
            int row = 2;

            ProcessDirectories(directoriesToScan, worksheet, ref row);

            for (int i = 1; i <= 9; i++)
            {
                worksheet.Column(i).AutoFit();
            }

            package.Save();
        }

        Console.WriteLine($"Merged report saved to {reportFileName}");
        return reportFileName;
    }

    static void PopulateHeaders(ExcelWorksheet worksheet)
    {
        worksheet.Cells[1, 1].Value = "Folder Name";
        worksheet.Cells[1, 2].Value = "Full Path";
        worksheet.Cells[1, 3].Value = "Account";
        worksheet.Cells[1, 4].Value = "WriteRights";
        worksheet.Cells[1, 5].Value = "ReadRights";
        worksheet.Cells[1, 6].Value = "RightsInfo";
        worksheet.Cells[1, 7].Value = "OwnerName";
        worksheet.Cells[1, 8].Value = "OwnerLogin";
        worksheet.Cells[1, 9].Value = "LastAccessTime";

        worksheet.Column(9).Style.Numberformat.Format = "dd.MM.yyyy HH:mm:ss";
    }

    static void ProcessDirectories(IEnumerable<string> directories, ExcelWorksheet worksheet, ref int row)
    {
        foreach (string dir in directories)
        {
            Console.Write($"\rProcessing: {dir}");
            AnalyzeDirectory(dir, worksheet, ref row);
        }
    }

    static void AnalyzeDirectory(string directoryPath, ExcelWorksheet worksheet, ref int row)
    {
        DirectoryInfo dirInfo;
        try
        {
            dirInfo = new DirectoryInfo(directoryPath);
        }
        catch
        {
            return;
        }

        DirectorySecurity dirSecurity;
        try
        {
            dirSecurity = dirInfo.GetAccessControl();
        }
        catch
        {
            return;
        }

        string ownerName = "(Unknown)";
        string ownerLogin = "(Unknown)";
        try
        {
            var ownerSid = dirSecurity.GetOwner(typeof(SecurityIdentifier));
            if (ownerSid != null)
            {
                var account = ownerSid.Translate(typeof(NTAccount)) as NTAccount;
                ownerName = account?.Value ?? ownerSid.Value;
                ownerLogin = ownerName.Split('\\').Last();
            }
        }
        catch
        {
            ownerName = "(Access Denied)";
            ownerLogin = "(Access Denied)";
        }

        string lastAccessTimeStr = "(Not Available)";
        try
        {
            if (dirInfo.Exists)
                lastAccessTimeStr = dirInfo.LastAccessTime.ToString("dd.MM.yyyy HH:mm:ss");
        }
        catch { }

        AuthorizationRuleCollection rules;
        try
        {
            rules = dirSecurity.GetAccessRules(true, true, typeof(NTAccount));
        }
        catch
        {
            return;
        }

        foreach (FileSystemAccessRule rule in rules)
        {
            string accountName;
            try
            {
                accountName = rule.IdentityReference.Translate(typeof(NTAccount)).Value;
            }
            catch
            {
                accountName = rule.IdentityReference.Value;
            }

            FileSystemRights rights = rule.FileSystemRights;

            bool hasRead = (rights & (FileSystemRights.ReadData | FileSystemRights.Read)) != 0 ||
                           (rights & FileSystemRights.ReadAndExecute) != 0 ||
                           (rights & FileSystemRights.ReadPermissions) != 0;

            bool hasWrite = (rights & (FileSystemRights.WriteData | FileSystemRights.Write)) != 0 ||
                            (rights & (FileSystemRights.CreateFiles | FileSystemRights.AppendData)) != 0 ||
                            (rights & FileSystemRights.Modify) != 0 ||
                            (rights & FileSystemRights.FullControl) != 0;

            worksheet.Cells[row, 1].Value = dirInfo.Name;
            worksheet.Cells[row, 2].Value = dirInfo.FullName;
            worksheet.Cells[row, 3].Value = accountName;
            worksheet.Cells[row, 4].Value = hasWrite;
            worksheet.Cells[row, 5].Value = hasRead;
            worksheet.Cells[row, 6].Value = rights.ToString();
            worksheet.Cells[row, 7].Value = ownerName;
            worksheet.Cells[row, 8].Value = ownerLogin;
            worksheet.Cells[row, 9].Value = lastAccessTimeStr;

            row++;
        }
    }

    static void LogError(string path, string logFilePath)
    {
        try
        {
            File.AppendAllText(logFilePath, $"Invalid or inaccessible directory: {path}{Environment.NewLine}");
        }
        catch { }

        Console.WriteLine($"Error: {path} - logged to '{logFilePath}'");
    }

    static void ShowHelp()
    {
        Console.WriteLine(@"
Permission Audit Tool Help
Usage: PermissionAuditTool.exe [options] <path>...

Options:
  -recursive          Scan subdirectories recursively.
  -merge              Merge results into a single Excel file.
  -sharedonly         Only scan directories that are shared (network shares).
  -smbsharesonly <srv>  Retrieve and analyze all disk shares from the specified server.
  -username <user>    Specify username for authentication (password entered interactively).
  -file <path>        Read list of directories from a text file.
  /?                  Show this help.

Examples:
  # Analyze local shared folders
  PermissionAuditTool.exe -sharedonly C:\Data -recursive

  # Analyze all shares on a remote server
  PermissionAuditTool.exe -smbsharesonly fileserver01 -username CORP\Admin -merge

  # Read paths from file
  PermissionAuditTool.exe -file paths.txt

Note:
  - When using -username, password is entered securely (not echoed).
  - Authentication is done via 'net use' and released after completion.
  - Only disk shares (Type = 0) are processed.
  - Generated Excel report is opened automatically.");
    }
}