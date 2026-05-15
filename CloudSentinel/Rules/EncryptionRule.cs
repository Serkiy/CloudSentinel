using System.Collections.Generic;
using System.Text.Json;
using CloudSentinel.Model;

namespace CloudSentinel.Rules
{
    public class EncryptionRule : IRule
    {
        public string RuleId => "ENC-001";

        public IEnumerable<Finding> Analyze(JsonDocument plan)
        {
            var findings = new List<Finding>();

            if (!plan.RootElement.TryGetProperty("resource_changes", out JsonElement resourceChanges))
                return findings;

            foreach (JsonElement resource in resourceChanges.EnumerateArray())
            {
                if (!resource.TryGetProperty("type", out JsonElement typeEl))
                    continue;

                string resourceType = typeEl.GetString() ?? "";

                if (resourceType != "aws_ebs_volume" &&
                    resourceType != "aws_db_instance" &&
                    resourceType != "aws_s3_bucket")
                    continue;

                if (!resource.TryGetProperty("change", out JsonElement change))
                    continue;

                if (!change.TryGetProperty("after", out JsonElement after))
                    continue;

                string resourceName = resource.TryGetProperty("address", out JsonElement address)
                    ? address.GetString() ?? "unknown"
                    : "unknown";

                if (resourceType == "aws_ebs_volume")
                {
                    if (after.TryGetProperty("encrypted", out JsonElement enc)
                        && enc.GetBoolean() == false)
                    {
                        findings.Add(new Finding(
                            RuleId: RuleId,
                            ResourceName: resourceName,
                            Description: "EBS volume is not encrypted. Data stored on this volume " +
                                         "is readable if the underlying storage is accessed directly.",
                            Remediation: "Set encrypted = true on your aws_ebs_volume resource. " +
                                         "You may also specify a KMS key with kms_key_id for additional control.",
                            Severity: Severity.High
                        ));
                    }
                }
                else if (resourceType == "aws_db_instance")
                {
                    if (after.TryGetProperty("storage_encrypted", out JsonElement dbEnc)
                        && dbEnc.GetBoolean() == false)
                    {
                        findings.Add(new Finding(
                            RuleId: RuleId,
                            ResourceName: resourceName,
                            Description: "RDS database instance has storage encryption disabled. " +
                                         "Database files, backups, and snapshots are stored unencrypted.",
                            Remediation: "Set storage_encrypted = true on your aws_db_instance resource. " +
                                         "Note: encryption cannot be enabled on an existing instance — " +
                                         "a snapshot restore to a new encrypted instance is required.",
                            Severity: Severity.High
                        ));
                    }
                }
                else if (resourceType == "aws_s3_bucket")
                {
                    if (!after.TryGetProperty("server_side_encryption_configuration", out _))
                    {
                        findings.Add(new Finding(
                            RuleId: RuleId,
                            ResourceName: resourceName,
                            Description: "S3 bucket does not have server-side encryption configured. " +
                                         "Objects stored in this bucket are not encrypted at rest.",
                            Remediation: "Add a server_side_encryption_configuration block to your " +
                                         "aws_s3_bucket resource with AES256 or aws:kms encryption.",
                            Severity: Severity.High
                        ));
                    }
                }
            }

            return findings;
        }
    }
}