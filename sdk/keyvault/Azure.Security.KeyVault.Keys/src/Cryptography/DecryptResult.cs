using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Azure.Security.KeyVault.Keys.Cryptography
{
    public struct DecryptResult : IJsonDeserializable
    {
        private const string KeyIdPropertyName = "kid";
        private const string PlaintextPropertyName = "value";

        public string KeyId { get; private set; }

        public byte[] Plaintext { get; private set; }

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
                    case PlaintextPropertyName:
                        Plaintext = Base64Url.Decode(prop.Value.GetString());
                        break;
                }
            }
        }
    }
}
