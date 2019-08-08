using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Azure.Security.KeyVault.Keys.Cryptography
{
    /// <summary>
    /// 
    /// </summary>
    public struct EncryptResult : IJsonDeserializable
    {
        private const string KeyIdPropertyName = "kid";
        private const string CiphertextPropertyName = "value";
        private const string IvPropertyName = "iv";
        private const string AuthenticationDataPropertyName = "aad";
        private const string AuthenticationTagPropertyName = "tag";

        /// <summary>
        /// 
        /// </summary>
        public string KeyId { get; internal set; }

        /// <summary>
        /// 
        /// </summary>
        public byte[] Ciphertext { get; internal set; }

        /// <summary>
        /// 
        /// </summary>
        public byte[] Iv { get; internal set; }

        /// <summary>
        /// 
        /// </summary>
        public byte[] AuthenticationData { get; internal set; }

        /// <summary>
        /// 
        /// </summary>
        public byte[] AuthenticationTag { get; internal set; }

        /// <summary>
        /// 
        /// </summary>
        public EncryptionAlgorithm Algorithm { get; internal set; }

        void IJsonDeserializable.ReadProperties(JsonElement json)
        {
            foreach (JsonProperty prop in json.EnumerateObject())
            {
                switch (prop.Name)
                {
                    case KeyIdPropertyName:
                        KeyId = prop.Value.GetString();
                        break;
                    case CiphertextPropertyName:
                        Ciphertext = Base64Url.Decode(prop.Value.GetString());
                        break;
                    case IvPropertyName:
                        Iv = Base64Url.Decode(prop.Value.GetString());
                        break;
                    case AuthenticationDataPropertyName:
                        AuthenticationData = Base64Url.Decode(prop.Value.GetString());
                        break;
                    case AuthenticationTagPropertyName:
                        AuthenticationTag = Base64Url.Decode(prop.Value.GetString());
                        break;
                }
            }
        }
    }
}
