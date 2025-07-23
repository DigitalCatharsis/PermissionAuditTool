using System.Security.AccessControl;
using System.Security.Principal;
using OfficeOpenXml; // EPPlus

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
        List<string> directoriesToScan = new List<string>();
        string logFilePath = "ErrorLog.txt";

        // Parse command line arguments
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
                case "-file":
                    if (i + 1 < args.Length && File.Exists(args[i + 1]))
                    {
                        directoriesToScan.AddRange(File.ReadLines(args[i + 1])
                            .Where(line => !string.IsNullOrWhiteSpace(line)));
                        i++; // Skip the next argument as it's the file path
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

        try
        {
            if (mergeResults)
            {
                GenerateMergedAccessReport(directoriesToScan, recursiveScan);
            }
            else
            {
                foreach (string directoryPath in directoriesToScan)
                {
                    if (Directory.Exists(directoryPath))
                    {
                        GenerateAccessReport(directoryPath, recursiveScan);
                    }
                    else
                    {
                        LogError(directoryPath, logFilePath);
                    }
                }
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

        // Notify user about the creation of the log file
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
  -recursive      Perform a recursive scan of all subdirectories.
  -merge          Merge results into a single output file.
  -file <path>    Read a list of directories from a text file.
  /?              Display this help message.

Examples:
  PermissionAuditTool.exe C:\Users\Public
  PermissionAuditTool.exe -recursive C:\Projects
  PermissionAuditTool.exe -file C:\list_of_directories.txt
  PermissionAuditTool.exe -merge -file C:\list_of_directories.txt

Note: The tool will generate an Excel report and log any errors to 'ErrorLog.txt'.
");
    }

    static void GenerateAccessReport(string directoryPath, bool recursiveScan)
    {
        string reportFileName = $"AccessReport_{DateTime.Now:yyyy.MM.dd.HHmmss}_{Path.GetFileName(directoryPath)}.xlsx";
        using (ExcelPackage excelPackage = new ExcelPackage(new FileInfo(reportFileName)))
        {
            ExcelWorksheet worksheet = excelPackage.Workbook.Worksheets.Add("Access Report");
            PopulateHeaders(worksheet);

            int row = 2;
            var directories = GetDirectories(directoryPath, recursiveScan);
            ProcessDirectories(directories, worksheet, ref row);

            // Auto-fit columns
            for (int i = 1; i <= 5; i++)
            {
                worksheet.Column(i).AutoFit();
            }

            excelPackage.Save();
        }

        Console.WriteLine($"Report saved to {reportFileName}");
    }

    static void GenerateMergedAccessReport(List<string> directoriesToScan, bool recursiveScan)
    {
        string reportFileName = $"AccessReport_Merged_{DateTime.Now:yyyy.MM.dd.HHmmss}.xlsx";
        using (ExcelPackage excelPackage = new ExcelPackage(new FileInfo(reportFileName)))
        {
            ExcelWorksheet worksheet = excelPackage.Workbook.Worksheets.Add("Access Report");
            PopulateHeaders(worksheet);

            int row = 2;
            foreach (string directoryPath in directoriesToScan)
            {
                if (!Directory.Exists(directoryPath))
                {
                    LogError(directoryPath, "ErrorLog.txt");
                    continue;
                }

                var directories = GetDirectories(directoryPath, recursiveScan);
                ProcessDirectories(directories, worksheet, ref row);
            }

            // Auto-fit columns
            for (int i = 1; i <= 5; i++)
            {
                worksheet.Column(i).AutoFit();
            }

            excelPackage.Save();
        }

        Console.WriteLine($"Merged report saved to {reportFileName}");
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

        // Set date format for LastAccessTime column
        worksheet.Column(9).Style.Numberformat.Format = "dd/MM/yyyy HH:mm:ss";
    }

    static void ProcessDirectories(IEnumerable<string> directories, ExcelWorksheet worksheet, ref int row)
    {
        foreach (var dir in directories)
        {
            Console.Write($"\rProcessing directory: {dir}");
            AnalyzeDirectory(dir, worksheet, ref row);
        }
    }

    static List<string> GetDirectories(string directoryPath, bool recursiveScan)
    {
        var directories = new List<string> { directoryPath };

        if (recursiveScan)
        {
            directories.AddRange(Directory.EnumerateDirectories(directoryPath, "*", SearchOption.AllDirectories));
        }

        return directories.Distinct().OrderBy(d => d).ToList();
    }

    static void AnalyzeDirectory(string directoryPath, ExcelWorksheet worksheet, ref int row)
    {
        DirectoryInfo directoryInfo = new DirectoryInfo(directoryPath);
        DirectorySecurity directorySecurity = directoryInfo.GetAccessControl();

        // Correctly get owner information
        var ownerSid = directoryInfo.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        string ownerName = "";
        string ownerLogin = "";

        if (ownerSid != null)
        {
            try
            {
                // Try to translate SID to NTAccount
                ownerName = ownerSid.Translate(typeof(NTAccount)).ToString();
                ownerLogin = ownerName.Split('\\').LastOrDefault(); // Extract just the username part
            }
            catch (IdentityNotMappedException)
            {
                // If translation fails, use SID directly
                ownerName = ownerSid.Value;
                ownerLogin = ownerName;
            }
        }

        // Get last access time (if available)
        DateTime? lastAccessTime = null;
        try
        {
            lastAccessTime = directoryInfo.LastAccessTime;
        }
        catch (UnauthorizedAccessException)
        {
            // Some directories may not have LastAccessTime set due to system policies
        }

        foreach (FileSystemAccessRule rule in directorySecurity.GetAccessRules(true, true, typeof(NTAccount)))
        {
            bool writeRights = (rule.FileSystemRights & FileSystemRights.Write) == FileSystemRights.Write;
            bool readRights = (rule.FileSystemRights & FileSystemRights.Read) == FileSystemRights.Read;

            worksheet.Cells[row, 1].Value = directoryInfo.Name;
            worksheet.Cells[row, 2].Value = directoryInfo.FullName;
            worksheet.Cells[row, 3].Value = rule.IdentityReference.Value;
            worksheet.Cells[row, 4].Value = writeRights;
            worksheet.Cells[row, 5].Value = readRights;
            worksheet.Cells[row, 6].Value = rule.FileSystemRights.ToString();
            worksheet.Cells[row, 7].Value = ownerName;
            worksheet.Cells[row, 8].Value = ownerLogin;
            worksheet.Cells[row, 9].Value = lastAccessTime.HasValue ? lastAccessTime.Value : "(Not Available)";

            row++;
        }
    }

    static void LogError(string path, string logFilePath)
    {
        using (StreamWriter writer = File.AppendText(logFilePath))
        {
            writer.WriteLine($"Invalid or inaccessible directory: {path}");
        }
        Console.WriteLine($"Error: Invalid or inaccessible directory: {path}. Logged to '{logFilePath}'.");
    }
}
