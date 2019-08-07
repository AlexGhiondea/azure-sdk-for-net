﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Azure.Security.KeyVault.Keys.Cryptography
{
    public enum KeyWrapAlgorithm
    {
        RSAOAEP,
        RSA15,
        RSAOAEP256
    }

    internal static class KeyWrapAlgorithmExtensions
    {
        public static string GetName(this KeyWrapAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case KeyWrapAlgorithm.RSAOAEP:
                    return "RSA-OAEP";
                case KeyWrapAlgorithm.RSA15:
                    return "RSA1_5";
                case KeyWrapAlgorithm.RSAOAEP256:
                    return "RSA-OAEP-256";
                default:
                    return null;
            }
        }
    }
}
