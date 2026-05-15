using System.Collections.Generic;
using System.Text.Json;
using CloudSentinel.Model;

namespace CloudSentinel.Rules
{
    public class LoggingRule : IRule
    {
        public string RuleId => "LOG-001";

        public IEnumerable<Finding> Analyze(JsonDocument plan)
        {
            var findings = new List<Finding>();

            if (!plan.RootElement.TryGetProperty("resource_changes", out JsonElement resourceChanges))
                return findings;

            bool cloudTrailFound = false;

            foreach (JsonElement resource in resourceChanges.EnumerateArray())
            {
                if (!resource.TryGetProperty("type", out JsonElement type))
                    continue;

                if (type.GetString() != "aws_cloudtrail")
                    continue;

                cloudTrailFound = true;

                if (!resource.TryGetProperty("change", out JsonElement change))
                    continue;

                if (!change.TryGetProperty("after", out JsonElement after))
                    continue;

                string resourceName = resource.TryGetProperty("address", out JsonElement address)
                    ? address.GetString() ?? "unknown"
                    : "unknown";

                if (after.TryGetProperty("enable_logging", out JsonElement logging)
                    && logging.GetBoolean() == false)
                {
                    findings.Add(new Finding(
                        RuleId: RuleId,
                        ResourceName: resourceName,
                        Description: "CloudTrail has logging explicitly disabled. API activity in " +
                                     "this AWS account is not being recorded, making security " +
                                     "incidents undetectable and unauditable.",
                        Remediation: "Set enable_logging = true on your aws_cloudtrail resource. " +
                                     "Ensure the trail is also configured to log to a protected S3 bucket.",
                        Severity: Severity.Medium
                    ));
                }
            }

            if (!cloudTrailFound)
            {
                findings.Add(new Finding(
                    RuleId: RuleId,
                    ResourceName: "aws_cloudtrail (missing)",
                    Description: "No CloudTrail resource was found in this Terraform plan. " +
                                 "Without CloudTrail, there is no audit log of API activity " +
                                 "in this AWS account.",
                    Remediation: "Add an aws_cloudtrail resource to your Terraform configuration " +
                                 "with enable_logging = true and an appropriate S3 bucket for log storage.",
                    Severity: Severity.Medium
                ));
            }

            return findings;
        }
    }
}