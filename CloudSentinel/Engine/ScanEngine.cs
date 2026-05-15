using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using CloudSentinel.Model;
using CloudSentinel.Rules;

namespace CloudSentinel.Engine
{
    public class ScanEngine
    {
        private readonly List<IRule> _rules = new List<IRule>
        {
            new OpenSecurityGroupRule(),
            new PublicStorageRule(),
            new IamWildcardRule(),
            new EncryptionRule(),
            new LoggingRule()
        };

        public ScanResult Run(JsonDocument plan)
        {
            var findings = _rules
                .SelectMany(rule => rule.Analyze(plan))
                .ToList();

            return new ScanResult(findings);
        }
    }
}