namespace CloudSentinel.Models
{
	public record Finding(

		string RuleId,
		string ResourceName,
		string Description,
		string Remediation,
		Severity Severity

	);
}