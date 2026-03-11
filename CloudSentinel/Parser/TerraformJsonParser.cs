using System;
using System.IO;
using System.Text.Json;

namespace CloudSentinel.Parser
{
	public class TerraformJsonParser
	{
		private readonly string _filePath;

		public TerraformJsonParser(string filePath)
		{
			_filePath = filePath;
		}

		public JsonDocument Parse()
		{
			if (!File.Exists(_filePath))
			{
				throw new FileNotFoundException(
					$"Terraform plan file not found at: {_filePath}"
				);
			}

			string json = File.ReadAllText(_filePath);

			if (string.IsNullOrWhiteSpace(json))
			{
				throw new InvalidOperationException(
					"The Terraform plan file is empty."
				);
			}

			try
			{
				return JsonDocument.Parse(json);
			}
			catch (JsonException ex)
			{
				throw new InvalidOperationException(
					$"The file is not valid JSON: {ex.Message}"
				);
			}
		}
	}
}