// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Xml.Serialization;

namespace Microsoft.CodeAnalysis.Sarif.Converters.NessusObjectModel
{
    public class PluginsPreferences
    {
        [XmlElement("item")]
        public List<Item> Items { get; set; } = new List<Item>();
    }
}
