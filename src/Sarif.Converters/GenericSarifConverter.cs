// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.Converters
{
    public class GenericSarifConverter : ToolFileConverterBase
    {
        public override string ToolName => ToolFormat.GenericSarif;

        public override void Convert(Stream input, IResultLogWriter output, OptionallyEmittedData dataToInsert)
        {
            input = input ?? throw new ArgumentNullException(nameof(input));
            output = output ?? throw new ArgumentNullException(nameof(output));

            var serializer = new JsonSerializer() { };

            using (var reader = new JsonTextReader(new StreamReader(input)))
            {
                SarifLog log = serializer.Deserialize<SarifLog>(reader);

                foreach (Run run in log.Runs)
                {
                    if (run?.Tool?.Driver?.Rules?.Count > 0)
                    {
                        foreach (ReportingDescriptor rule in run.Tool.Driver.Rules)
                        {
                            if (rule.Help != null)
                            {
                                if (!string.IsNullOrWhiteSpace(rule.Help.Markdown) && string.IsNullOrWhiteSpace(rule.Help.Text))
                                {
                                    rule.Help.Text = rule.Help.Markdown;
                                }
                                else if (!string.IsNullOrWhiteSpace(rule.Help.Text) && string.IsNullOrWhiteSpace(rule.Help.Markdown))
                                {
                                    rule.Help.Markdown = rule.Help.Text;
                                }
                                else if (string.IsNullOrEmpty(rule.Help.Text) && string.IsNullOrEmpty(rule.Help.Markdown))
                                {
                                    rule.Help = null;
                                }
                            }

                        }
                    }
                    
                    if (run?.Results != null)
                    {
                        foreach (Result runResult in run?.Results)
                        {
                            if (runResult.Fingerprints == null || runResult.Fingerprints.Count == 0)
                            {
                                if (runResult.PartialFingerprints == null || runResult.PartialFingerprints.Count == 0)
                                {
                                    IDictionary<string, string> partialFingerprints = new Dictionary<string, string>();
                                    partialFingerprints.Add("id", HashUtilities.ComputeSha256HashValue(runResult.RuleId).ToLower());

                                    if (runResult.Locations != null)
                                    {
                                        foreach (Location runResultLocation in runResult.Locations)
                                        {
                                            PhysicalLocation physicalLocation = runResultLocation.PhysicalLocation;
                                            if (physicalLocation != null)
                                            {
                                                if (physicalLocation.ArtifactLocation != null)
                                                {
                                                    partialFingerprints.Add("artifacturi",
                                                        HashUtilities
                                                            .ComputeSha256HashValue(physicalLocation.ArtifactLocation.Uri
                                                                .ToString()).ToLower());
                                                }

                                                Region physicalLocationRegion = physicalLocation.Region;

                                                if (physicalLocationRegion != null)
                                                {
                                                    partialFingerprints.Add("startline",
                                                        HashUtilities
                                                            .ComputeSha256HashValue(physicalLocationRegion.StartLine
                                                                .ToString()).ToLower());

                                                    partialFingerprints.Add("endline",
                                                        HashUtilities
                                                            .ComputeSha256HashValue(physicalLocationRegion.EndLine
                                                                .ToString()).ToLower());
                                                }
                                            }
                                        }
                                    }

                                    if (partialFingerprints.Any())
                                    {
                                        runResult.PartialFingerprints = partialFingerprints;
                                    }
                                }
                            }
                        }
                    }
                }

                PersistResults(output, log);
            }
        }
    }
}
