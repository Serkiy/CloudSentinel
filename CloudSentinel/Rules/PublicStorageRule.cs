using System.Collections.Generic;
using System.Text.Json;
using CloudSentinel.Model;

namespace CloudSentinel.Rules
{
    public class PublicStorageRule : IRule
    {
        public string RuleId => "STG-001";

        public IEnumerable<Finding> Analyze(JsonDocument plan)
        {
            var findings = new List<Finding>();

            if (!plan.RootElement.TryGetProperty("resource_changes", out JsonElement resourceChanges))
                return findings;

            foreach (JsonElement resource in resourceChanges.EnumerateArray())
            {
                if (!resource.TryGetProperty("type", out JsonElement type))
                    continue;

                if (type.GetString() != "aws_s3_bucket_public_access_block")
                    continue;

                if (!resource.TryGetProperty("change", out JsonElement change))
                    continue;

                if (!change.TryGetProperty("after", out JsonElement after))
                    continue;

                string resourceName = resource.TryGetProperty("address", out JsonElement address)
                    ? address.GetString() ?? "unknown"
                    : "unknown";

                if (after.TryGetProperty("block_public_acls", out JsonElement blockAcls)
                    && blockAcls.GetBoolean() == false)
                {
                    findings.Add(new Finding(
                        RuleId: RuleId,
                        ResourceName: resourceName,
                        Description: "S3 bucket does not block public ACLs. Objects in this bucket " +
                                     "can be made publicly accessible via ACL grants.",
                        Remediation: "Set block_public_acls = true in your aws_s3_bucket_public_access_block " +
                                     "resource to prevent public ACL grants on this bucket.",
                        Severity: Severity.Critical
                    ));
                }

                if (after.TryGetProperty("block_public_policy", out JsonElement blockPolicy)
                    && blockPolicy.GetBoolean() == false)
                {
                    findings.Add(new Finding(
                        RuleId: RuleId,
                        ResourceName: resourceName,
                        Description: "S3 bucket does not block public bucket policies. A bucket policy " +
                                     "could expose this bucket's contents to the public internet.",
                        Remediation: "Set block_public_policy = true in your aws_s3_bucket_public_access_block " +
                                     "resource to prevent public bucket policies.",
                        Severity: Severity.Critical
                    ));
                }
            }

            return findings;
        }
    }
}