// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.Converters.SnykOpenSourceObjectModel
{
    public class LegalInstruction
    {
        [JsonProperty("licenseName")]
        public string LicenseName { get; set; }

        [JsonProperty("legalContent")]
        public string LegalContent { get; set; }
    }
}