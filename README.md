<div align="center">

<img src="https://img.shields.io/badge/C%23-.NET-512BD4?style=for-the-badge&logo=dotnet&logoColor=white" />
<img src="https://img.shields.io/badge/Platform-AWS%20%7C%20Azure%20%7C%20K8s-232F3E?style=for-the-badge&logo=amazonaws&logoColor=white" />
<img src="https://img.shields.io/badge/Input-Terraform-7B42BC?style=for-the-badge&logo=terraform&logoColor=white" />
<img src="https://img.shields.io/badge/Output-PDF%20Report-E53935?style=for-the-badge&logo=adobeacrobatreader&logoColor=white" />
<img src="https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge" />

<br/><br/>

# CloudSentinel

### *Analyze cloud infrastructure misconfigurations. Score your risk. Fix what matters.*

CloudSentinel is a static analysis tool for Terraform infrastructure plans.  
It detects common cloud security misconfigurations across AWS, Azure, and Kubernetes,  
assigns a **weighted risk score**, and generates a **structured PDF report** with remediation guidance.

<br/>

[Getting Started](#getting-started) · [What It Detects](#what-it-detects) · [Risk Scoring](#risk-scoring) · [Project Structure](#project-structure) · [Roadmap](#roadmap)

</div>

---

## The Problem

In cloud environments, most security breaches are not caused by sophisticated attacks — they are caused by **misconfiguration**:

- A storage bucket left publicly accessible
- An IAM policy granting `*` permissions to everything
- Encryption quietly disabled on a database
- A security group open to `0.0.0.0/0` on port 22
- CloudTrail turned off with no audit trail

These are not rare edge cases. They are everyday mistakes made under time pressure, in complex systems, by engineers focused on shipping features rather than auditing access rules.

**CloudSentinel catches them before they reach production.**

---

## Features

- Parses **Terraform plan JSON** — no cloud credentials required, fully offline analysis
- **5 rule categories** covering the most critical misconfiguration classes
- **Weighted risk scoring** with an overall 0–100 score and letter grade (A–F)
- **PDF report generation** with executive summary, findings table, and per-finding remediation
- **Extensible rule engine** — add new rules by implementing one interface
- **CLI-first design** — integrates cleanly into CI/CD pipelines

---

## What It Detects

| Rule | Severity | What It Catches |
|------|----------|-----------------|
| Open Security Groups | Critical | Ingress rules allowing `0.0.0.0/0` on any port |
| Public Storage | Critical | S3 buckets or Azure Blob containers with public access enabled |
| Wildcard IAM Permissions | High | IAM policies using `*` for actions or resources |
| Disabled Encryption | High | Unencrypted EBS volumes, RDS instances, or S3 buckets |
| Missing Logging | Medium | CloudTrail disabled, VPC Flow Logs absent |

New rules can be added by creating a class that implements `IRule` and registering it in `ScanEngine.cs`.

---

## Risk Scoring

Each finding contributes to an overall risk score based on its severity:

| Severity | Points Per Finding | Score Range | Grade |
|----------|--------------------|-------------|-------|
| Critical | 10 | 0 – 20 | A — Excellent |
| High | 7 | 21 – 40 | B — Good |
| Medium | 4 | 41 – 60 | C — Moderate Risk |
| Low | 1 | 61 – 80 | D — High Risk |
| | | 81 – 100 | F — Critical Risk |

The final score is normalized to a 0–100 scale. A configuration with zero findings returns **Score: 0 / Grade: A**.

---

## Getting Started

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download) or later
- [Terraform CLI](https://developer.hashicorp.com/terraform/install) (to generate the input file)

### 1. Clone the repository

```bash
git clone https://github.com/your-username/cloudsentinel.git
cd cloudsentinel
```

### 2. Generate your Terraform plan JSON

```bash
cd your-terraform-project/
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
```

### 3. Run the analyzer

```bash
dotnet run --project CloudSentinel -- --input path/to/tfplan.json --output report.pdf
```

You can also choose the output format: PDF (default), JSON, or SARIF. Use `--format` (or `-f`) with `pdf`, `json`, or `sarif`:

```bash
# PDF (default)
dotnet run --project CloudSentinel -- --input input/tfplan.json --output output/report.pdf

# JSON
dotnet run --project CloudSentinel -- --input input/tfplan.json --output output/report.json --format json

# SARIF
dotnet run --project CloudSentinel -- --input input/tfplan.json --output output/report.sarif --format sarif
```

### 4. Open the report

The PDF report will be saved to the path specified by `--output`. It contains:
- Overall risk score and letter grade
- Findings grouped by severity
- Resource names and descriptions for each finding
- Specific remediation steps

---

## Project Structure

```
CloudSentinel/
│
├── CloudSentinel.sln
├── CloudSentinel/
│   ├── Program.cs                      # Entry point and CLI argument parsing
│   │
│   ├── Models/
│   │   ├── Finding.cs                  # Single misconfiguration finding
│   │   ├── Severity.cs                 # Enum: Critical, High, Medium, Low
│   │   └── ScanResult.cs               # All findings + computed risk score
│   │
│   ├── Parser/
│   │   └── TerraformJsonParser.cs      # Loads and exposes the Terraform plan JSON
│   │
│   ├── Rules/
│   │   ├── IRule.cs                    # Interface all rules must implement
│   │   ├── OpenSecurityGroupRule.cs
│   │   ├── PublicStorageRule.cs
│   │   ├── IamWildcardRule.cs
│   │   ├── EncryptionRule.cs
│   │   └── LoggingRule.cs
│   │
│   ├── Engine/
│   │   └── ScanEngine.cs               # Runs all rules, collects findings
│   │
│   ├── Scoring/
│   │   └── RiskScorer.cs               # Weighted score + letter grade
│   │
│   └── Report/
│       └── PdfReportGenerator.cs       # Builds PDF report using QuestPDF
│
├── input/
│   └── tfplan.json                     # Place your Terraform plan JSON here
│
└── output/
    └── report.pdf                      # Generated reports appear here
```

---

## Adding a New Rule

1. Create a new file in `Rules/`, e.g. `S3VersioningRule.cs`
2. Implement the `IRule` interface:

```csharp
public class S3VersioningRule : IRule
{
    public IEnumerable<Finding> Analyze(JsonDocument plan)
    {
        yield return new Finding(
            RuleId: "S3-003",
            ResourceName: "aws_s3_bucket.my_bucket",
            Description: "S3 bucket does not have versioning enabled.",
            Remediation: "Add a versioning block with enabled = true to your aws_s3_bucket resource.",
            Severity: Severity.Medium
        );
    }
}
```

---

## Running Tests

This repository includes an xUnit test project that exercises the rule engine against the sample `input/tfplan.json` file.

Run tests with:

```bash
dotnet test
```

The test scaffolding also demonstrates how to parse a Terraform plan and exercise the `ScanEngine` in an integration-style test.


3. Register it in `ScanEngine.cs`:

```csharp
private readonly List<IRule> _rules = new()
{
    new OpenSecurityGroupRule(),
    new PublicStorageRule(),
    new IamWildcardRule(),
    new EncryptionRule(),
    new LoggingRule(),
    new S3VersioningRule()   // add here
};
```

No other changes are required.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `System.Text.Json` | Parses Terraform plan JSON (built into .NET) |
| `QuestPDF` | PDF report generation |
| `System.CommandLine` | CLI argument parsing |

Install NuGet packages:

```bash
dotnet add package QuestPDF
dotnet add package System.CommandLine
```

---

## Roadmap

- [x] Terraform plan JSON parsing
- [x] Core rule engine with 5 rule categories
- [x] Weighted risk scoring (0–100 + grade)
- [x] PDF report with remediation guidance
- [ ] SARIF output format for GitHub Advanced Security integration
- [ ] Live AWS account scanning via SDK
- [ ] Kubernetes manifest scanning (RBAC, PodSecurity)
- [ ] CI/CD sample workflows (GitHub Actions, Azure DevOps)
- [ ] Rule severity configuration via JSON config file

---

## Contributing

Contributions are welcome. To add a new rule, fix a bug, or improve the report layout:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-new-rule`
3. Commit your changes: `git commit -m 'Add S3 versioning rule'`
4. Push to the branch: `git push origin feature/my-new-rule`
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>Built with C# · .NET 8 · QuestPDF · Terraform</sub>
</div>
