using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Azure.Security.KeyVault.Keys.Cryptography
{
    public struct VerifyResult : IJsonDeserializable
    {
        private const string KeyIdPropertyName = "kid";
        private const string ValidPropertyName = "value";

        public string KeyId { get; private set; }

        public bool Valid { get; private set; }

        public SignatureAlgorithm Algorithm { get; internal set; }

        void IJsonDeserializable.ReadProperties(JsonElement json)
        {
            foreach (JsonProperty prop in json.EnumerateObject())
            {
                switch (prop.Name)
                {
                    case KeyIdPropertyName:
                        KeyId = prop.Value.GetString();
                        break;
                    case ValidPropertyName:
                        Valid = prop.Value.GetBoolean();
                        break;
                }
            }
        }
    }
}
