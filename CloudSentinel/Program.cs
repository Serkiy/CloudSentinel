using System;
using CloudSentinel.Engine;
using CloudSentinel.Parser;
using CloudSentinel.Report;
using CloudSentinel.Scoring;

string? inputFile = null;
string? outputFile = null;
string format = "pdf"; // pdf | json | sarif

// Simple argument parsing
for (int i = 0; i < args.Length; i++)
{
    if ((args[i] == "--input" || args[i] == "-i") && i + 1 < args.Length)
    {
        inputFile = args[i + 1];
        i++;
    }
    else if ((args[i] == "--output" || args[i] == "-o") && i + 1 < args.Length)
    {
        outputFile = args[i + 1];
        i++;
    }
    else if ((args[i] == "--format" || args[i] == "-f") && i + 1 < args.Length)
    {
        format = args[i + 1].ToLowerInvariant();
        i++;
    }
}

// Validate required arguments
if (string.IsNullOrEmpty(inputFile) || string.IsNullOrEmpty(outputFile))
{
    Console.WriteLine("CloudSentinel — Cloud Misconfiguration Analyzer");
    Console.WriteLine();
    Console.WriteLine("Usage: CloudSentinel --input <file> --output <file>");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine("  --input, -i    Path to the Terraform plan JSON file (required)");
    Console.WriteLine("  --output, -o   Path where the PDF report will be saved (required)");
    Environment.Exit(1);
}

Console.WriteLine("─────────────────────────────────────────");
Console.WriteLine("  CloudSentinel Security Analyzer");
Console.WriteLine("─────────────────────────────────────────");
Console.WriteLine($"  Input  : {inputFile}");
Console.WriteLine($"  Output : {outputFile}");
Console.WriteLine();

try
{
    // Step 1: Parse the Terraform plan JSON
    Console.WriteLine("[1/4] Parsing Terraform plan...");
    var parser = new TerraformJsonParser(inputFile);
    var plan   = parser.Parse();

    // Step 2: Run the scan engine against all rules
    Console.WriteLine("[2/4] Running security rules...");
    var engine = new ScanEngine();
    var result = engine.Run(plan);

    // Step 3: Calculate the risk score and grade
    Console.WriteLine("[3/4] Calculating risk score...");
    var scorer = new RiskScorer();
    scorer.Score(result);

    // Step 4: Generate the report in requested format
    Console.WriteLine("[4/4] Generating report...");
    switch (format)
    {
        case "json":
            var jsonGen = new JsonReportGenerator();
            jsonGen.Generate(result, outputFile);
            break;
        case "sarif":
            var sarifGen = new SarifReportGenerator();
            sarifGen.Generate(result, outputFile);
            break;
        default:
            var pdfGen = new PdfReportGenerator();
            pdfGen.Generate(result, outputFile);
            break;
    }

    // Summary
    Console.WriteLine();
    Console.WriteLine("─────────────────────────────────────────");
    Console.WriteLine("  Scan Complete");
    Console.WriteLine("─────────────────────────────────────────");
    Console.WriteLine($"  Risk Score    : {result.RiskScore} / 100");
    Console.WriteLine($"  Grade         : {result.Grade}");
    Console.WriteLine($"  Total Findings: {result.TotalFindings}");
    Console.WriteLine($"    Critical    : {result.Critical.Count()}");
    Console.WriteLine($"    High        : {result.High.Count()}");
    Console.WriteLine($"    Medium      : {result.Medium.Count()}");
    Console.WriteLine($"    Low         : {result.Low.Count()}");
    Console.WriteLine();
    Console.WriteLine($"  Report saved to: {outputFile}");
    Console.WriteLine("─────────────────────────────────────────");
}
catch (Exception ex)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"\n  Error: {ex.Message}");
    Console.ResetColor();
    Environment.Exit(1);
}
