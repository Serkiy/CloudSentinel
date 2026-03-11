using System.Collections.Generic;
using System.Text.Json;
using CloudSentinel.Models;

namespace CloudSentinel.Rules
{
	public class OpenSecurityGroupRule : IRule
	{
		public string RuleId => "NET-001";

		public IEnumerable<Finding> Analyze(JsonDocument plan)
		{
			var findings = new List<Finding>();

			if (!plan.RootElement.TryGetProperty("resource_changes", out JsonElement resourceChanges))
				return findings;

			foreach (JsonElement resource in resourceChanges.EnumerateArray())
			{
				if (!resource.TryGetProperty("type", out JsonElement type))
					continue;

				if (type.GetString() != "aws_security_group")
					continue;

				if (!resource.TryGetProperty("change", out JsonElement change))
					continue;

				if (!change.TryGetProperty("after", out JsonElement after))
					continue;

				string resourceName = resource.TryGetProperty("address", out JsonElement address)
					? address.GetString() ?? "unknown"
					: "unknown";

				if (!after.TryGetProperty("ingress", out JsonElement ingressRules))
					continue;

				foreach (JsonElement ingress in ingressRules.EnumerateArray())
				{
					if (!ingress.TryGetProperty("cidr_blocks", out JsonElement cidrBlocks))
						continue;

					foreach (JsonElement cidr in cidrBlocks.EnumerateArray())
					{
						if (cidr.GetString() == "0.0.0.0/0")
						{
							findings.Add(new Finding(
								RuleId: RuleId,
								ResourceName: resourceName,
								Description: "Security group has an ingress rule open to 0.0.0.0/0, " +
											 "allowing unrestricted access from the entire internet.",
								Remediation: "Restrict ingress CIDR blocks to known, trusted IP ranges. " +
											 "Never expose ports to 0.0.0.0/0 in production environments.",
								Severity: Severity.Critical
							));
						}
					}
				}
			}

			return findings;
		}
	}
}