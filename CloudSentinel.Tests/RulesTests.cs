using System.IO;
using System.Linq;
using CloudSentinel.Engine;
using CloudSentinel.Parser;
using Xunit;

namespace CloudSentinel.Tests
{
    public class RulesTests
    {
        [Fact]
        public void EngineDetectsExpectedFindingsFromSamplePlan()
        {
            // Resolve input path from the test runtime folder to repository input/tfplan.json
            var planPath = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "..", "input", "tfplan.json"));
            var parser = new TerraformJsonParser(planPath);
            var plan = parser.Parse();

            var engine = new ScanEngine();
            var result = engine.Run(plan);

            // Expecting 3 Critical, 5 High, 1 Medium => 9 total
            Assert.Equal(9, result.TotalFindings);
            Assert.Equal(3, result.Critical.Count());
            Assert.Equal(5, result.High.Count());
            Assert.Equal(1, result.Medium.Count());
        }
    }
}
