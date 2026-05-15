using System.IO;
using System.Linq;
using System.Text.Json;
using CloudSentinel.Model;

namespace CloudSentinel.Report
{
    public class SarifReportGenerator
    {
        public void Generate(ScanResult result, string outputPath)
        {
            static string MapLevel(Severity s) => s switch
            {
                Severity.Critical => "error",
                Severity.High => "error",
                Severity.Medium => "warning",
                Severity.Low => "note",
                _ => "warning"
            };

            var sarif = new
            {
                version = "2.1.0",
                runs = new[]
                {
                    new
                    {
                        tool = new { driver = new { name = "CloudSentinel" } },
                        results = result.Findings.Select(f => new
                        {
                            ruleId = f.RuleId,
                            level = MapLevel(f.Severity),
                            message = new { text = f.Description }
                        }).ToArray()
                    }
                }
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(outputPath, JsonSerializer.Serialize(sarif, options));
        }
    }
}
