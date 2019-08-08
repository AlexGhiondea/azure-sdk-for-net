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
    public struct UnwrapResult : IJsonDeserializable
    {
        private const string KeyIdPropertyName = "kid";
        private const string KeyPropertyName = "value";

        /// <summary>
        /// 
        /// </summary>
        public string KeyId { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        public byte[] Key { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        public KeyWrapAlgorithm Algorithm { get; internal set; }

        void IJsonDeserializable.ReadProperties(JsonElement json)
        {
            foreach (JsonProperty prop in json.EnumerateObject())
            {
                switch (prop.Name)
                {
                    case KeyIdPropertyName:
                        KeyId = prop.Value.GetString();
                        break;
                    case KeyPropertyName:
                        Key = Base64Url.Decode(prop.Value.GetString());
                        break;
                }
            }
        }
    }
}
