using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using OfficeOpenXml;

class PermissionAuditTool
{
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
        List<string> directoriesToScan = new List<string>();
        string logFilePath = "ErrorLog.txt";

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
                    if (Directory.Exists(args[i]))
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

        if (directoriesToScan.Count == 0)
        {
            Console.WriteLine("No valid directories to scan. Use /? for help.");
            return;
        }

        // Получаем ВСЕ расшаренные папки на машине
        var allSharedPaths = GetSharedFoldersViaNetShare();

        List<string> finalDirectories = new List<string>();

        foreach (string rootPath in directoriesToScan)
        {
            if (sharedOnly)
            {
                // Фильтруем расшаренные папки: только те, что внутри rootPath
                var sharedInRoot = allSharedPaths
                    .Where(shared => IsSubPath(shared, rootPath))
                    .ToList();

                if (recursiveScan)
                {
                    // Также ищем расшаренные папки в подкаталогах
                    var sharedInSubdirs = allSharedPaths
                        .Where(shared => shared.StartsWith(rootPath, StringComparison.OrdinalIgnoreCase) && !IsDirectChild(shared, rootPath))
                        .ToList();
                    sharedInRoot.AddRange(sharedInSubdirs);
                }

                finalDirectories.AddRange(sharedInRoot);
            }
            else
            {
                // Обычный режим: сканируем rootPath и подкаталоги, если recursive
                finalDirectories.Add(rootPath);
                if (recursiveScan)
                {
                    try
                    {
                        finalDirectories.AddRange(Directory.EnumerateDirectories(rootPath, "*", SearchOption.AllDirectories));
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
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

        try
        {
            if (mergeResults)
            {
                reportFileName = GenerateMergedAccessReport(finalDirectories);
            }
            else
            {
                foreach (string directoryPath in finalDirectories)
                {
                    reportFileName = GenerateAccessReport(directoryPath);
                }
            }

            // Автоматически открыть последний созданный файл
            if (!string.IsNullOrEmpty(reportFileName) && File.Exists(reportFileName))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = reportFileName,
                    UseShellExecute = true // Обязательно для открытия в Windows
                });
            }
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("Access denied. Please run the application as an administrator.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }

        if (File.Exists(logFilePath) && new FileInfo(logFilePath).Length > 0)
        {
            Console.WriteLine($"Errors logged to '{logFilePath}'.");
        }
    }

    static void ShowHelp()
    {
        Console.WriteLine(@"
Permission Audit Tool Help
Usage: PermissionAuditTool.exe [options] <directoryPath1> [<directoryPath2> ...]

Options:
  -recursive      Include subdirectories in the scan.
  -merge          Merge results from multiple directories into a single output file.
  -sharedonly     Only scan directories that are shared (published as network shares).
  -file <path>    Read a list of directories from a text file (one per line).
  /?              Display this help message.

Examples:
  PermissionAuditTool.exe C:\temp
  PermissionAuditTool.exe -recursive C:\Projects
  PermissionAuditTool.exe -sharedonly C:\temp
  PermissionAuditTool.exe -sharedonly -recursive C:\temp
  PermissionAuditTool.exe -merge -sharedonly C:\temp
  PermissionAuditTool.exe -file directories.txt

Note: With -sharedonly, only shared folders within the specified path(s) will be scanned.
The tool generates an Excel report (.xlsx) and logs errors to 'ErrorLog.txt'.
The generated report will be opened automatically after creation.");
    }

    static List<string> GetSharedFoldersViaNetShare()
    {
        var sharedPaths = new List<string>();
        try
        {
            var startInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "net",
                Arguments = "share",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Environment.SystemDirectory
            };

            using (var process = System.Diagnostics.Process.Start(startInfo))
            {
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                string[] lines = output.Split(
                    new[] { Environment.NewLine },
                    StringSplitOptions.None
                );

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

    static bool IsDirectChild(string child, string parent)
    {
        try
        {
            var parentDir = new DirectoryInfo(Path.GetFullPath(parent));
            var childDir = new DirectoryInfo(Path.GetFullPath(child));
            return childDir.Parent?.FullName.Equals(parentDir.FullName, StringComparison.OrdinalIgnoreCase) ?? false;
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
}