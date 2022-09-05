﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.CodeAnalysis.Sarif.Visitors
{
    public class SuppressVisitor : SarifRewritingVisitor
    {
        private readonly bool uuids;
        private readonly IEnumerable<string> resultsGuids;
        private readonly string alias;
        private readonly bool timestamps;
        private readonly DateTime timeUtc;
        private readonly DateTime expiryUtc;
        private readonly int expiryInDays;
        private readonly string justification;
        private readonly SuppressionStatus suppressionStatus;

        public SuppressVisitor(string justification,
                               string alias,
                               bool uuids,
                               bool timestamps,
                               int expiryInDays,
                               SuppressionStatus suppressionStatus,
                               IEnumerable<string> resultsGuids)
        {
            this.alias = alias;
            this.uuids = uuids;
            this.timestamps = timestamps;
            this.timeUtc = DateTime.UtcNow;
            this.expiryInDays = expiryInDays;
            this.justification = justification;
            this.suppressionStatus = suppressionStatus;
            this.expiryUtc = this.timeUtc.AddDays(expiryInDays);
            this.resultsGuids = resultsGuids;
        }

        public override Result VisitResult(Result node)
        {
            if (node.Suppressions == null)
            {
                node.Suppressions = new List<Suppression>();
            }



            var suppression = new Suppression
            {
                Status = suppressionStatus,
                Justification = justification,
                Kind = SuppressionKind.External,
            };

            if (!string.IsNullOrWhiteSpace(alias))
            {
                suppression.SetProperty(nameof(alias), alias);
            }

            if (this.uuids)
            {
                suppression.Guid = Guid.NewGuid().ToString(SarifConstants.GuidFormat);
            }

            if (timestamps)
            {
                suppression.SetProperty(nameof(timeUtc), timeUtc);
            }

            if (expiryInDays > 0)
            {
                suppression.SetProperty(nameof(expiryUtc), expiryUtc);
            }

            if (this.resultsGuids != null)
            {
                if (this.resultsGuids.Contains(node.Guid, StringComparer.OrdinalIgnoreCase))
                {
                    node.Suppressions.Add(suppression);
                }
            }
            else
            {
                node.Suppressions.Add(suppression);
            }

            return base.VisitResult(node);
        }
    }
}
