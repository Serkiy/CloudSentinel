using System.Collections.Generic;
using System.Linq;

namespace CloudSentinel.Models
{
	public class ScanResult
	{
		public List<Finding> Findings { get; }
		public int RiskScore { get; set; }
		public string Grade { get; set; }

		public ScanResult(List<Finding> findings)
		{
			Findings = findings;
			Grade = "A";
		}

		public IEnumerable<Finding> Critical =>
			Findings.Where(f => f.Severity == Severity.Critical);

		public IEnumerable<Finding> High =>
			Findings.Where(f => f.Severity == Severity.High);

		public IEnumerable<Finding> Medium =>
			Findings.Where(f => f.Severity == Severity.Medium);

		public IEnumerable<Finding> Low =>
			Findings.Where(f => f.Severity == Severity.Low);

		public int TotalFindings => Findings.Count;
	}
}