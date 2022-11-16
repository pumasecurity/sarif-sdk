// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.Converters.SnykOpenSourceObjectModel;

namespace Microsoft.CodeAnalysis.Sarif.Converters
{
    public class SnykLicenseConverter : ToolFileConverterBase
    {
        private readonly LogReader<List<Test>> logReader;
        private const string _CWE_IDENTIFIER_KEY = "CWE";
        private const string _CVE_IDENTIFIER_KEY = "CVE";
        private const string _LICENSE_RESULT_TYPE = "license";

        public SnykLicenseConverter()
        {
            logReader = new SnykOpenSourceReader();
        }

        public override string ToolName => ToolFormat.SnykLicense;

        public override void Convert(Stream input, IResultLogWriter output, OptionallyEmittedData dataToInsert)
        {
            input = input ?? throw new ArgumentNullException(nameof(input));
            output = output ?? throw new ArgumentNullException(nameof(output));

            //Read Snyk data
            List<Test> snykTests = logReader.ReadLog(input);

            //Init objects
            var log = new SarifLog();
            log.Runs = new List<Run>();
            var run = new Run();
            run.Tool = new Tool();
            run.Results = new List<Result>();

            //Set driver details
            run.Tool.Driver = CreateDriver();

            //Set the list of tool rules & results
            run.Tool.Driver.Rules = new List<ReportingDescriptor>();
            foreach (Test test in snykTests.Where(i => !i.Ok))
            {
                foreach (Vulnerability vulnerability in test.Vulnerabilities.Where(i => !string.IsNullOrEmpty(i.Type) && i.Type.Equals(_LICENSE_RESULT_TYPE)))
                {
                    //Add rule id if not exits in collection
                    if (!run.Tool.Driver.Rules.Any(i => i.Id == vulnerability.Id))
                    {
                        run.Tool.Driver.Rules.Add(CreateReportDescriptor(vulnerability));
                    }

                    //Add result for the rule if does not previously exist (there are duplicates???)
                    if (!run.Results.Any(i => i.RuleId == vulnerability.Id && i.Locations.Any(l => l.PhysicalLocation.ArtifactLocation.Uri.ToString().Equals(test.DisplayTargetFile))))
                    {
                        run.Results.Add(CreateResult(vulnerability, test));
                    }
                }
            }

            log.Runs.Add(run);
            PersistResults(output, log);
        }

        private ToolComponent CreateDriver()
        {

            var driver = new ToolComponent();

            driver.Name = this.ToolName;
            driver.FullName = this.ToolName;
            //JSON schema has no version information. Pin to 1.0 for now.
            driver.Version = "1.0.0";
            driver.SemanticVersion = "1.0.0";
            driver.InformationUri = new Uri("https://docs.snyk.io/products/snyk-open-source/licenses");

            return driver;
        }

        private ReportingDescriptor CreateReportDescriptor(Vulnerability item)
        {
            ReportingDescriptor descriptor = new ReportingDescriptor();

            descriptor.Id = item.Id;
            descriptor.Name = item.License;
            descriptor.ShortDescription = new MultiformatMessageString()
            {
                Text = $"{item.Title} in {item.Name}@{item.Version}",
                Markdown = $"{item.Title} in {item.Name}@{item.Version}",
            };
            descriptor.FullDescription = new MultiformatMessageString()
            {
                Text = $"{item.Title} in {item.Name}@{item.Version}",
                Markdown = $"{item.Title} in {item.Name}@{item.Version}",
            };

            //Help text includes refs + triage advice
            StringBuilder sbHelp = new StringBuilder();
            if (item.References.Count() > 0)
            {
                sbHelp.AppendLine("References:");
                foreach (Reference reference in item.References)
                {
                    sbHelp.AppendFormat("{0}: {1}{2}", reference.Title, reference.Url, Environment.NewLine);
                }
            }

            if (!string.IsNullOrEmpty(item.Insights?.TriageAdvice))
            {
                sbHelp.AppendLine("");
                sbHelp.AppendLine("Triage Advice:");
                sbHelp.Append(item.Insights.TriageAdvice);
            }

            if (sbHelp.Length > 0)
            {
                descriptor.Help = new MultiformatMessageString()
                {
                    Text = sbHelp.ToString(),
                    Markdown = sbHelp.ToString(),
                };
            }

            //Set the type
            descriptor.SetProperty("type", item.Type);

            //Use for GH Security Advisories
            FailureLevel level = FailureLevel.None;
            double rank = RankConstants.None;
            getResultSeverity(item.Cvss3BaseScore, item.SeverityWithCritical, out level, out rank);
            descriptor.SetProperty("security-severity", rank.ToString("F1"));

            //Tags for GH filtering
            var tags = new List<string>()
            {
                "security",
                item.License,
                item.PackageManager,
            };

            descriptor.SetProperty("tags", tags);

            return descriptor;
        }

        private Result CreateResult(Vulnerability item, Test test)
        {
            //Set message text
            var message = string.Empty;
            message = string.Join(" ", item.LegalInstructions.Select(i => i.LegalContent.Trim()));

            //set the result metadata
            Result result = new Result
            {
                RuleId = item.Id,
                Message = new Message
                {
                    Text = message,
                },
            };

            //Set the kind, level, and rank based on cvss3 score
            FailureLevel level = FailureLevel.None;
            double rank = RankConstants.None;
            getResultSeverity(item.Cvss3BaseScore, item.SeverityWithCritical, out level, out rank);

            //Set the properties
            result.Kind = ResultKind.Fail;
            result.Level = level;
            result.Rank = rank;

            //Set the location properties
            PhysicalLocation location = new PhysicalLocation()
            {
                ArtifactLocation = new ArtifactLocation()
                {
                    Uri = new Uri(test.DisplayTargetFile, UriKind.Relative),
                    UriBaseId = "%SRCROOT%",
                },
                Region = new Region()
                {
                    StartLine = 1,
                }
            };
            result.Locations = new List<Location>();
            result.Locations.Add(new Location()
            {
                PhysicalLocation = location,
            });

            //Set the unique fingerprint
            var fingerprints = new List<string>() {
                item.Id,
                item.Type,
                item.PackageManager,
                item.PackageName,
                item.Version,
                test.DisplayTargetFile,
            };

            result.Fingerprints = new Dictionary<string, string>();
            result.Fingerprints.Add("0", HashUtilities.ComputeSha256HashValue(string.Join(".", fingerprints)).ToLower());

            result.SetProperty("packageManager", item.PackageManager);
            result.SetProperty("packageName", item.PackageName);
            result.SetProperty("packageVersion", item.Version);

            if (item.Semver.Vulnerable.Any())
            {
                result.SetProperty("semanticVersion", item.Semver.Vulnerable);
            }

            if (item.FixedIn.Any())
            {
                result.SetProperty("patchedVersion", item.FixedIn);
            }

            return result;
        }

        private void getResultSeverity(double cvss3score, string severityWithCritical, out FailureLevel level, out double rank)
        {
            // Default values
            level = FailureLevel.None;
            rank = RankConstants.None;

            if (severityWithCritical.Equals("critical", StringComparison.OrdinalIgnoreCase))
            {
                level = FailureLevel.Error;
                rank = RankConstants.Critical;
            }
            else if (severityWithCritical.Equals("high", StringComparison.OrdinalIgnoreCase))
            {
                level = FailureLevel.Error;
                rank = RankConstants.High;
            }
            else if (severityWithCritical.Equals("medium", StringComparison.OrdinalIgnoreCase))
            {
                level = FailureLevel.Warning;
                rank = RankConstants.Medium;
            }
            else if (severityWithCritical.Equals("low", StringComparison.OrdinalIgnoreCase))
            {
                level = FailureLevel.Note;
                rank = RankConstants.Low;
            }
        }
    }
}
