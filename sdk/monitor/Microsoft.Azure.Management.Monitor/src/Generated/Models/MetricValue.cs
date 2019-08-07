// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Management.Monitor.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// Represents a metric value.
    /// </summary>
    public partial class MetricValue
    {
        /// <summary>
        /// Initializes a new instance of the MetricValue class.
        /// </summary>
        public MetricValue()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the MetricValue class.
        /// </summary>
        /// <param name="timeStamp">the timestamp for the metric value in ISO
        /// 8601 format.</param>
        /// <param name="average">the average value in the time range.</param>
        /// <param name="minimum">the least value in the time range.</param>
        /// <param name="maximum">the greatest value in the time range.</param>
        /// <param name="total">the sum of all of the values in the time
        /// range.</param>
        /// <param name="count">the number of samples in the time range. Can be
        /// used to determine the number of values that contributed to the
        /// average value.</param>
        public MetricValue(System.DateTime timeStamp, double? average = default(double?), double? minimum = default(double?), double? maximum = default(double?), double? total = default(double?), double? count = default(double?))
        {
            TimeStamp = timeStamp;
            Average = average;
            Minimum = minimum;
            Maximum = maximum;
            Total = total;
            Count = count;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the timestamp for the metric value in ISO 8601 format.
        /// </summary>
        [JsonProperty(PropertyName = "timeStamp")]
        public System.DateTime TimeStamp { get; set; }

        /// <summary>
        /// Gets or sets the average value in the time range.
        /// </summary>
        [JsonProperty(PropertyName = "average")]
        public double? Average { get; set; }

        /// <summary>
        /// Gets or sets the least value in the time range.
        /// </summary>
        [JsonProperty(PropertyName = "minimum")]
        public double? Minimum { get; set; }

        /// <summary>
        /// Gets or sets the greatest value in the time range.
        /// </summary>
        [JsonProperty(PropertyName = "maximum")]
        public double? Maximum { get; set; }

        /// <summary>
        /// Gets or sets the sum of all of the values in the time range.
        /// </summary>
        [JsonProperty(PropertyName = "total")]
        public double? Total { get; set; }

        /// <summary>
        /// Gets or sets the number of samples in the time range. Can be used
        /// to determine the number of values that contributed to the average
        /// value.
        /// </summary>
        [JsonProperty(PropertyName = "count")]
        public double? Count { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="Rest.ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            //Nothing to validate
        }
    }
}
