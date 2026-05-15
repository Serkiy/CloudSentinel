using System;
using System.Collections.Generic;
using System.Text.Json;
using CloudSentinel.Model;

namespace CloudSentinel.Rules
{
    public class IamWildcardRule : IRule
    {
        public string RuleId => "IAM-001";

        public IEnumerable<Finding> Analyze(JsonDocument plan)
        {
            var findings = new List<Finding>();

            if (!plan.RootElement.TryGetProperty("resource_changes", out JsonElement resourceChanges))
                return findings;

            foreach (JsonElement resource in resourceChanges.EnumerateArray())
            {
                if (!resource.TryGetProperty("type", out JsonElement type))
                    continue;

                if (type.GetString() != "aws_iam_policy")
                    continue;

                if (!resource.TryGetProperty("change", out JsonElement change))
                    continue;

                if (!change.TryGetProperty("after", out JsonElement after))
                    continue;

                string resourceName = resource.TryGetProperty("address", out JsonElement address)
                    ? address.GetString() ?? "unknown"
                    : "unknown";

                if (!after.TryGetProperty("policy", out JsonElement policyElement))
                    continue;

                string policyJson = policyElement.GetString() ?? "";
                if (string.IsNullOrWhiteSpace(policyJson))
                    continue;

                try
                {
                    using var policyDoc = JsonDocument.Parse(policyJson);
                    var root = policyDoc.RootElement;

                    if (!root.TryGetProperty("Statement", out JsonElement statements))
                        continue;

                    foreach (JsonElement statement in statements.EnumerateArray())
                    {
                        // Helper to check string or array for wildcard
                        static bool HasWildcard(JsonElement el)
                        {
                            if (el.ValueKind == JsonValueKind.String)
                                return el.GetString() == "*";

                            if (el.ValueKind == JsonValueKind.Array)
                            {
                                foreach (var item in el.EnumerateArray())
                                {
                                    if (item.ValueKind == JsonValueKind.String && item.GetString() == "*")
                                        return true;
                                }
                            }

                            return false;
                        }

                        // Check Action for wildcard (string or array)
                        if (statement.TryGetProperty("Action", out JsonElement action) && HasWildcard(action))
                        {
                            findings.Add(new Finding(
                                RuleId: RuleId,
                                ResourceName: resourceName,
                                Description: "IAM policy grants wildcard (*) Action, allowing the " +
                                             "attached principal to perform any AWS action.",
                                Remediation: "Replace Action: '*' with only the specific actions this " +
                                             "principal needs. Follow the principle of least privilege.",
                                Severity: Severity.High
                            ));
                        }

                        // Check Resource for wildcard (string or array)
                        if (statement.TryGetProperty("Resource", out JsonElement res) && HasWildcard(res))
                        {
                            findings.Add(new Finding(
                                RuleId: RuleId,
                                ResourceName: resourceName,
                                Description: "IAM policy grants access to wildcard (*) Resource, " +
                                             "allowing actions on every resource in the AWS account.",
                                Remediation: "Replace Resource: '*' with the specific ARNs of the " +
                                             "resources this principal needs to access.",
                                Severity: Severity.High
                            ));
                        }
                    }
                }
                catch (JsonException)
                {
                    // Malformed inner policy JSON — skip this resource
                }
            }

            return findings;
        }
    }
}