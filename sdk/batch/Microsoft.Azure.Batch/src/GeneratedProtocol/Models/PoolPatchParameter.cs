// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Batch.Protocol.Models
{
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// The set of changes to be made to a Pool.
    /// </summary>
    public partial class PoolPatchParameter
    {
        /// <summary>
        /// Initializes a new instance of the PoolPatchParameter class.
        /// </summary>
        public PoolPatchParameter()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the PoolPatchParameter class.
        /// </summary>
        /// <param name="startTask">A Task to run on each Compute Node as it
        /// joins the Pool. The Task runs when the Compute Node is added to the
        /// Pool or when the Compute Node is restarted.</param>
        /// <param name="certificateReferences">A list of Certificates to be
        /// installed on each Compute Node in the Pool.</param>
        /// <param name="applicationPackageReferences">A list of Packages to be
        /// installed on each Compute Node in the Pool.</param>
        /// <param name="metadata">A list of name-value pairs associated with
        /// the Pool as metadata.</param>
        public PoolPatchParameter(StartTask startTask = default(StartTask), IList<CertificateReference> certificateReferences = default(IList<CertificateReference>), IList<ApplicationPackageReference> applicationPackageReferences = default(IList<ApplicationPackageReference>), IList<MetadataItem> metadata = default(IList<MetadataItem>))
        {
            StartTask = startTask;
            CertificateReferences = certificateReferences;
            ApplicationPackageReferences = applicationPackageReferences;
            Metadata = metadata;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets a Task to run on each Compute Node as it joins the
        /// Pool. The Task runs when the Compute Node is added to the Pool or
        /// when the Compute Node is restarted.
        /// </summary>
        /// <remarks>
        /// If this element is present, it overwrites any existing StartTask.
        /// If omitted, any existing StartTask is left unchanged.
        /// </remarks>
        [JsonProperty(PropertyName = "startTask")]
        public StartTask StartTask { get; set; }

        /// <summary>
        /// Gets or sets a list of Certificates to be installed on each Compute
        /// Node in the Pool.
        /// </summary>
        /// <remarks>
        /// If this element is present, it replaces any existing Certificate
        /// references configured on the Pool. If omitted, any existing
        /// Certificate references are left unchanged. For Windows Nodes, the
        /// Batch service installs the Certificates to the specified
        /// Certificate store and location. For Linux Compute Nodes, the
        /// Certificates are stored in a directory inside the Task working
        /// directory and an environment variable AZ_BATCH_CERTIFICATES_DIR is
        /// supplied to the Task to query for this location. For Certificates
        /// with visibility of 'remoteUser', a 'certs' directory is created in
        /// the user's home directory (e.g., /home/{user-name}/certs) and
        /// Certificates are placed in that directory.
        /// </remarks>
        [JsonProperty(PropertyName = "certificateReferences")]
        public IList<CertificateReference> CertificateReferences { get; set; }

        /// <summary>
        /// Gets or sets a list of Packages to be installed on each Compute
        /// Node in the Pool.
        /// </summary>
        /// <remarks>
        /// Changes to Package references affect all new Nodes joining the
        /// Pool, but do not affect Compute Nodes that are already in the Pool
        /// until they are rebooted or reimaged. If this element is present, it
        /// replaces any existing Package references. If you specify an empty
        /// collection, then all Package references are removed from the Pool.
        /// If omitted, any existing Package references are left unchanged.
        /// </remarks>
        [JsonProperty(PropertyName = "applicationPackageReferences")]
        public IList<ApplicationPackageReference> ApplicationPackageReferences { get; set; }

        /// <summary>
        /// Gets or sets a list of name-value pairs associated with the Pool as
        /// metadata.
        /// </summary>
        /// <remarks>
        /// If this element is present, it replaces any existing metadata
        /// configured on the Pool. If you specify an empty collection, any
        /// metadata is removed from the Pool. If omitted, any existing
        /// metadata is left unchanged.
        /// </remarks>
        [JsonProperty(PropertyName = "metadata")]
        public IList<MetadataItem> Metadata { get; set; }

    }
}
