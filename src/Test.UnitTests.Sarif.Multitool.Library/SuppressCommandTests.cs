﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.Driver;

using Moq;

using Newtonsoft.Json;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.Multitool
{
    public class SuppressCommandTests
    {
        private const int DateTimeAssertPrecision = 500;
        private static readonly TestAssetResourceExtractor s_extractor = new TestAssetResourceExtractor(typeof(SuppressCommandTests));

        [Fact]
        public void SuppressCommand_ShouldReturnFailure_WhenBadArgumentsAreSupplied()
        {
            const string outputPath = @"c:\output.sarif";
            var optionsTestCases = new SuppressOptions[]
            {
                new SuppressOptions
                {
                    ExpiryInDays = -1
                },
                new SuppressOptions
                {
                    ExpiryInDays = 1,
                    Justification = string.Empty
                },
                new SuppressOptions
                {
                    ExpiryInDays = 1,
                    Justification = "some justification",
                    Status = SuppressionStatus.Rejected
                },
                new SuppressOptions
                {
                    ExpiryInDays = 1,
                    Justification = "some justification",
                    Status = SuppressionStatus.Accepted,
                    SarifOutputVersion = SarifVersion.Unknown
                },
                new SuppressOptions
                {
                    ExpiryInDays = -1,
                    Justification = "some justification",
                    OutputFilePath = outputPath,
                    Status = SuppressionStatus.Accepted
                },
                new SuppressOptions
                {
                    ExpiryInDays = 1,
                    Justification = "some justification",
                    OutputFilePath = outputPath,
                    Expression = "fail",
                    Status = SuppressionStatus.Accepted
                },
                new SuppressOptions
                {
                    ExpiryUtc = DateTime.UtcNow.AddDays(-1),
                    Justification = "some justification",
                    OutputFilePath = outputPath,
                    Status = SuppressionStatus.Accepted
                },
                new SuppressOptions
                {
                    ExpiryInDays = 1,
                    ExpiryUtc = DateTime.UtcNow.AddDays(1),
                    Justification = "some justification",
                    OutputFilePath = outputPath,
                    Status = SuppressionStatus.Accepted
                },
            };

            var mock = new Mock<IFileSystem>();
            mock.Setup(f => f.FileExists(outputPath))
                .Returns(false);

            foreach (SuppressOptions options in optionsTestCases)
            {
                var command = new SuppressCommand();
                command.Run(options).Should().Be(CommandBase.FAILURE);
            }
        }

        [Fact]
        public void SuppressCommand_ShouldNotFail_NullRun()
        {
            string filePath = "NullRun.sarif";
            string outFilePath = "NullRun.suppressed.sarif";
            File.WriteAllText(filePath, s_extractor.GetResourceText(filePath));

            var options = new SuppressOptions[]
            {
                new SuppressOptions
                {
                    Alias = "some alias",
                    InputFilePath = filePath,
                    OutputFilePath = outFilePath,
                    Justification = "justified",
                    Status = SuppressionStatus.Accepted,
                    Force = true
                },
                new SuppressOptions
                {
                    Expression = "RuleId == 'test rule'",
                    ResultsGuids = new List<string> { Guid.NewGuid().ToString() },
                    Alias = "some alias",
                    InputFilePath = filePath,
                    OutputFilePath = outFilePath,
                    Justification = "justified",
                    Status = SuppressionStatus.Accepted,
                    Force = true
                }
            };

            foreach (SuppressOptions option in options)
                RunAndVerifyExitCode(0, option);
        }

        [Fact]
        public void SuppressCommand_ShouldReturnSuccess_WhenCorrectArgumentsAreSupplied()
        {
            var optionsTestCases = new SuppressOptions[]
            {
                // new SuppressOptions
                // {
                //     Alias = "some alias",
                //     InputFilePath = @"C:\input.sarif",
                //     OutputFilePath = @"C:\output.sarif",
                //     Justification = "some justification",
                //     Status = SuppressionStatus.Accepted
                // },
                // new SuppressOptions
                // {
                //     InputFilePath = @"C:\input.sarif",
                //     OutputFilePath = @"C:\output.sarif",
                //     Justification = "some justification",
                //     Status = SuppressionStatus.UnderReview
                // },
                // new SuppressOptions
                // {
                //     Guids = true,
                //     InputFilePath = @"C:\input.sarif",
                //     OutputFilePath = @"C:\output.sarif",
                //     Justification = "some justification",
                //     Status = SuppressionStatus.Accepted
                // },
                // new SuppressOptions
                // {
                //     Guids = true,
                //     ExpiryInDays = 5,
                //     Timestamps = true,
                //     InputFilePath = @"C:\input.sarif",
                //     OutputFilePath = @"C:\output.sarif",
                //     Justification = "some justification",
                //     Status = SuppressionStatus.Accepted
                // },
                // new SuppressOptions
                // {
                //     Guids = true,
                //     ExpiryInDays = 5,
                //     Timestamps = true,
                //     InputFilePath = @"C:\input.sarif",
                //     OutputFilePath = @"C:\output.sarif",
                //     Justification = "some justification",
                //     Expression = "BaseLineState = \"New\"",
                //     Status = SuppressionStatus.Accepted
                // },
                // new SuppressOptions
                // {
                //     Guids = true,
                //     ExpiryInDays = 5,
                //     Timestamps = true,
                //     InputFilePath = @"C:\input.sarif",
                //     OutputFilePath = @"C:\output.sarif",
                //     Justification = "some justification",
                //     ResultsGuids = new List<string>() { "GUID"},
                //     Expression = string.Empty,
                //     Status = SuppressionStatus.Accepted
                // },
                // new SuppressOptions
                // {
                //     Guids = true,
                //     ExpiryInDays = 5,
                //     Timestamps = true,
                //     InputFilePath = @"C:\input.sarif",
                //     OutputFilePath = @"C:\output.sarif",
                //     Justification = "some justification",
                //     ResultsGuids = new List<string>() { "GUID", "GUID2"},
                //     Expression = "BaseLineState = \"New\"",
                //     Status = SuppressionStatus.Accepted
                // },
                // new SuppressOptions
                // {
                //     Guids = true,
                //     ExpiryInDays = 5,
                //     Timestamps = true,
                //     InputFilePath = @"C:\input.sarif",
                //     OutputFilePath = @"C:\output.sarif",
                //     Justification = "some justification",
                //     ResultsGuids = new List<string>() {},
                //     Expression = "BaseLineState = \"New\"",
                //     Status = SuppressionStatus.Accepted
                // },
                // new SuppressOptions
                // {
                //     Guids = true,
                //     ExpiryInDays = 5,
                //     Timestamps = true,
                //     InputFilePath = @"C:\input.sarif",
                //     OutputFilePath = @"C:\output.sarif",
                //     Justification = "some justification",
                //     ResultsGuids = new List<string>() {},
                //     Expression = "IsSuppressed == False",
                //     Status = SuppressionStatus.Accepted
                // },
                new SuppressOptions
                {
                    Guids = true,
                    ExpiryUtc = DateTime.UtcNow.AddDays(30),
                    Timestamps = true,
                    InputFilePath = @"C:\input.sarif",
                    OutputFilePath = @"C:\output.sarif",
                    Justification = "some justification",
                    ResultsGuids = new List<string>() {},
                    Expression = "IsSuppressed == False",
                    Status = SuppressionStatus.Accepted
                },
            };

            foreach (SuppressOptions options in optionsTestCases)
            {
                VerifySuppressCommand(options);
            }
        }

        private static void RunAndVerifyExitCode(int expectedExitCode, SuppressOptions options)
        {
            int exitCode = new SuppressCommand().Run(options);
            Assert.Equal(expectedExitCode, exitCode);
        }

        private static void VerifySuppressCommand(SuppressOptions options)
        {
            var current = new SarifLog
            {
                Runs = new List<Run>
                {
                    new Run
                    {
                        Results = new List<Result>
                        {
                            new Result
                            {
                                RuleId = "Test0001",
                                Guid = "GUID",
                                BaselineState = BaselineState.New
                            }
                        }
                    }
                }
            };

            var transformedContents = new StringBuilder();
            var currentStream = new MemoryStream(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(current)));

            var currentContents = new StringBuilder(JsonConvert.SerializeObject(current));
            var mockFileSystem = new Mock<IFileSystem>();

            mockFileSystem
                .Setup(x => x.FileReadAllText(options.InputFilePath))
                .Returns(JsonConvert.SerializeObject(current));

            mockFileSystem
                .Setup(x => x.FileOpenRead(options.InputFilePath))
                .Returns(() =>
                    currentStream);

            mockFileSystem
                .Setup(x => x.FileCreate(options.OutputFilePath))
                .Returns(() => new MemoryStreamToStringBuilder(transformedContents));

            var command = new SuppressCommand(mockFileSystem.Object);
            command.Run(options).Should().Be(CommandBase.SUCCESS);

            SarifLog suppressed = JsonConvert.DeserializeObject<SarifLog>(transformedContents.ToString());
            suppressed.Runs[0].Results[0].Suppressions.Should().NotBeNullOrEmpty();

            Suppression suppression = suppressed.Runs[0].Results[0].Suppressions[0];
            suppression.Status.Should().Be(options.Status);
            suppression.Kind.Should().Be(SuppressionKind.External);
            suppression.Justification.Should().Be(options.Justification);

            if (!string.IsNullOrWhiteSpace(options.Alias))
            {
                suppression.GetProperty("alias").Should().Be(options.Alias);
            }

            if (options.Guids)
            {
                suppression.Guid.Should().NotBeNullOrEmpty();
            }

            if (!string.IsNullOrWhiteSpace(options.Expression))
            {
                suppressed.Runs[0].Results[0].BaselineState.Should().Be(BaselineState.New);
            }

            if (options.Timestamps && suppression.TryGetProperty("timeUtc", out DateTime timeUtc))
            {
                timeUtc.Should().BeCloseTo(DateTime.UtcNow, DateTimeAssertPrecision);
            }

            if (options.ExpiryInDays > 0)
            {
                suppression.TryGetProperty("expiryUtc", out DateTime expiryInDaysUtc).Should().BeTrue();
                expiryInDaysUtc.Should().BeCloseTo(DateTime.UtcNow.AddDays(options.ExpiryInDays), DateTimeAssertPrecision);
            }

            if (options.ExpiryUtc.HasValue)
            {
                suppression.TryGetProperty("expiryUtc", out DateTime expiryUtc).Should().BeTrue();
                expiryUtc.Should().BeCloseTo(options.ExpiryUtc.Value, DateTimeAssertPrecision);
            }
        }
    }
}
