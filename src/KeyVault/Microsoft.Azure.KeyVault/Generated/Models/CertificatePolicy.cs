// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator 1.0.0.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

namespace Microsoft.Azure.KeyVault.Models
{
    using Azure;
    using KeyVault;
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Management policy for a certificate.
    /// </summary>
    public partial class CertificatePolicy
    {
        /// <summary>
        /// Initializes a new instance of the CertificatePolicy class.
        /// </summary>
        public CertificatePolicy() { }

        /// <summary>
        /// Initializes a new instance of the CertificatePolicy class.
        /// </summary>
        /// <param name="id">The certificate id.</param>
        /// <param name="keyProperties">Properties of the key backing a
        /// certificate.</param>
        /// <param name="secretProperties">Properties of the secret backing a
        /// certificate.</param>
        /// <param name="x509CertificateProperties">Properties of the X509
        /// component of a certificate.</param>
        /// <param name="lifetimeActions">Actions that will be performed by Key
        /// Vault over the lifetime of a certificate.</param>
        /// <param name="issuerParameters">Parameters for the issuer of the
        /// X509 component of a certificate.</param>
        /// <param name="attributes">The certificate attributes.</param>
        public CertificatePolicy(string id = default(string), KeyProperties keyProperties = default(KeyProperties), SecretProperties secretProperties = default(SecretProperties), X509CertificateProperties x509CertificateProperties = default(X509CertificateProperties), IList<LifetimeAction> lifetimeActions = default(IList<LifetimeAction>), IssuerParameters issuerParameters = default(IssuerParameters), CertificateAttributes attributes = default(CertificateAttributes))
        {
            Id = id;
            KeyProperties = keyProperties;
            SecretProperties = secretProperties;
            X509CertificateProperties = x509CertificateProperties;
            LifetimeActions = lifetimeActions;
            IssuerParameters = issuerParameters;
            Attributes = attributes;
        }

        /// <summary>
        /// Gets the certificate id.
        /// </summary>
        [JsonProperty(PropertyName = "id")]
        public string Id { get; protected set; }

        /// <summary>
        /// Gets or sets properties of the key backing a certificate.
        /// </summary>
        [JsonProperty(PropertyName = "key_props")]
        public KeyProperties KeyProperties { get; set; }

        /// <summary>
        /// Gets or sets properties of the secret backing a certificate.
        /// </summary>
        [JsonProperty(PropertyName = "secret_props")]
        public SecretProperties SecretProperties { get; set; }

        /// <summary>
        /// Gets or sets properties of the X509 component of a certificate.
        /// </summary>
        [JsonProperty(PropertyName = "x509_props")]
        public X509CertificateProperties X509CertificateProperties { get; set; }

        /// <summary>
        /// Gets or sets actions that will be performed by Key Vault over the
        /// lifetime of a certificate.
        /// </summary>
        [JsonProperty(PropertyName = "lifetime_actions")]
        public IList<LifetimeAction> LifetimeActions { get; set; }

        /// <summary>
        /// Gets or sets parameters for the issuer of the X509 component of a
        /// certificate.
        /// </summary>
        [JsonProperty(PropertyName = "issuer")]
        public IssuerParameters IssuerParameters { get; set; }

        /// <summary>
        /// Gets or sets the certificate attributes.
        /// </summary>
        [JsonProperty(PropertyName = "attributes")]
        public CertificateAttributes Attributes { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="Rest.ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (X509CertificateProperties != null)
            {
                X509CertificateProperties.Validate();
            }
            if (LifetimeActions != null)
            {
                foreach (var element in LifetimeActions)
                {
                    if (element != null)
                    {
                        element.Validate();
                    }
                }
            }
        }
    }
}

