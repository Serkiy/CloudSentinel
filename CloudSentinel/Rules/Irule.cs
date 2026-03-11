using System.Collections.Generic;
using System.Text.Json;
using CloudSentinel.Models;

namespace CloudSentinel.Rules
{
	public interface IRule
	{
		string RuleId { get; }
		IEnumerable<Finding> Analyze(JsonDocument plan);
	}
}