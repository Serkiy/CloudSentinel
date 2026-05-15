using System.IO;
using System.Linq;
using System.Text.Json;
using CloudSentinel.Model;

namespace CloudSentinel.Report
{
    public class JsonReportGenerator
    {
        public void Generate(ScanResult result, string outputPath)
        {
            var payload = new
            {
                result.RiskScore,
                result.Grade,
                result.TotalFindings,
                Findings = result.Findings.Select(f => new
                {
                    f.RuleId,
                    f.ResourceName,
                    f.Description,
                    f.Remediation,
                    Severity = f.Severity.ToString()
                }).ToArray()
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(payload, options);
            File.WriteAllText(outputPath, json);
        }
    }
}
