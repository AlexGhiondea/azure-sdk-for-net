// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Management.DataFactory.Models
{
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// A copy activity Netezza source.
    /// </summary>
    public partial class NetezzaSource : CopySource
    {
        /// <summary>
        /// Initializes a new instance of the NetezzaSource class.
        /// </summary>
        public NetezzaSource()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the NetezzaSource class.
        /// </summary>
        /// <param name="additionalProperties">Unmatched properties from the
        /// message are deserialized this collection</param>
        /// <param name="sourceRetryCount">Source retry count. Type: integer
        /// (or Expression with resultType integer).</param>
        /// <param name="sourceRetryWait">Source retry wait. Type: string (or
        /// Expression with resultType string), pattern:
        /// ((\d+)\.)?(\d\d):(60|([0-5][0-9])):(60|([0-5][0-9])).</param>
        /// <param name="maxConcurrentConnections">The maximum concurrent
        /// connection count for the source data store. Type: integer (or
        /// Expression with resultType integer).</param>
        /// <param name="query">A query to retrieve data from source. Type:
        /// string (or Expression with resultType string).</param>
        /// <param name="partitionOption">The partition mechanism that will be
        /// used for Netezza read in parallel. Possible values include: 'None',
        /// 'DataSlice', 'DynamicRange'</param>
        /// <param name="partitionSettings">The settings that will be leveraged
        /// for Netezza source partitioning.</param>
        public NetezzaSource(IDictionary<string, object> additionalProperties = default(IDictionary<string, object>), object sourceRetryCount = default(object), object sourceRetryWait = default(object), object maxConcurrentConnections = default(object), object query = default(object), string partitionOption = default(string), NetezzaPartitionSettings partitionSettings = default(NetezzaPartitionSettings))
            : base(additionalProperties, sourceRetryCount, sourceRetryWait, maxConcurrentConnections)
        {
            Query = query;
            PartitionOption = partitionOption;
            PartitionSettings = partitionSettings;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets a query to retrieve data from source. Type: string (or
        /// Expression with resultType string).
        /// </summary>
        [JsonProperty(PropertyName = "query")]
        public object Query { get; set; }

        /// <summary>
        /// Gets or sets the partition mechanism that will be used for Netezza
        /// read in parallel. Possible values include: 'None', 'DataSlice',
        /// 'DynamicRange'
        /// </summary>
        [JsonProperty(PropertyName = "partitionOption")]
        public string PartitionOption { get; set; }

        /// <summary>
        /// Gets or sets the settings that will be leveraged for Netezza source
        /// partitioning.
        /// </summary>
        [JsonProperty(PropertyName = "partitionSettings")]
        public NetezzaPartitionSettings PartitionSettings { get; set; }

    }
}
