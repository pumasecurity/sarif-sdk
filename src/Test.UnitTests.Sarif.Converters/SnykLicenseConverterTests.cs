using System;
using System.IO;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.Writers;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.Converters
{
    public class SnykLicenseConverterTests : ConverterTestsBase<SnykLicenseConverter>
    {
        [Fact]
        public void Converter_RequiresInputStream()
        {
            var converter = new SnykLicenseConverter();
            Action action = () => converter.Convert(input: null, output: new ResultLogObjectWriter(), dataToInsert: OptionallyEmittedData.None);
            action.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void Converter_RequiresResultLogWriter()
        {
            var converter = new SnykLicenseConverter();
            Action action = () => converter.Convert(input: new MemoryStream(), output: null, dataToInsert: OptionallyEmittedData.None);
            action.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void Converter_WhenInputIsEmpty_ReturnsNoResults()
        {
            string input = Extractor.GetResourceInputText("NoResults.json");
            string expectedOutput = Extractor.GetResourceExpectedOutputsText("NoResults.sarif");
            RunTestCase(input, expectedOutput);
        }

        [Fact]
        public void Converter_WhenResultRowIsInvalid_ReturnsNoResults()
        {
            string input = Extractor.GetResourceInputText("InvalidResults.json");
            string expectedOutput = Extractor.GetResourceExpectedOutputsText("NoResults.sarif");
            RunTestCase(input, expectedOutput);
        }

        [Fact]
        public void Converter_WhenInputContainsValidResults_ReturnsExpectedOutput()
        {
            string input = Extractor.GetResourceInputText("ValidResults.json");
            string expectedOutput = Extractor.GetResourceExpectedOutputsText("ValidResults.sarif");
            RunTestCase(input, expectedOutput);
        }

        [Fact]
        public void Converter_WhenInputContainsValidResult_ReturnsExpectedOutput()
        {
            string input = Extractor.GetResourceInputText("ValidResult.json");
            string expectedOutput = Extractor.GetResourceExpectedOutputsText("ValidResults.sarif");
            RunTestCase(input, expectedOutput);
        }

        private static readonly TestAssetResourceExtractor Extractor = new TestAssetResourceExtractor(typeof(SnykLicenseConverterTests));
        private const string ResourceNamePrefix = ToolFormat.SnykLicense;
    }
}
