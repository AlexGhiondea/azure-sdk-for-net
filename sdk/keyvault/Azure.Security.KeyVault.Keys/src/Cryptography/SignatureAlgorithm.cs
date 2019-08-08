﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Azure.Security.KeyVault.Keys.Cryptography
{
    /// <summary>
    /// 
    /// </summary>
    public enum SignatureAlgorithm
    {
        /// <summary>
        /// 
        /// </summary>
        RS256,

        /// <summary>
        /// 
        /// </summary>
        RS384,

        /// <summary>
        /// 
        /// </summary>
        RS512,

        /// <summary>
        /// 
        /// </summary>
        PS256,

        /// <summary>
        /// 
        /// </summary>
        PS384,

        /// <summary>
        /// 
        /// </summary>
        PS512,

        /// <summary>
        /// 
        /// </summary>
        ES256,

        /// <summary>
        /// 
        /// </summary>
        ES384,

        /// <summary>
        /// 
        /// </summary>
        ES512,

        /// <summary>
        /// 
        /// </summary>
        ES256K
    }

    internal static class SignatureAlgorithmExtensions
    {
        public static HashAlgorithm GetHashAlgorithm(this SignatureAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case SignatureAlgorithm.RS256:
                case SignatureAlgorithm.PS256:
                case SignatureAlgorithm.ES256:
                case SignatureAlgorithm.ES256K:
                    return SHA256.Create();
                case SignatureAlgorithm.RS384:
                case SignatureAlgorithm.PS384:
                case SignatureAlgorithm.ES384:
                    return SHA384.Create();
                case SignatureAlgorithm.RS512:
                case SignatureAlgorithm.PS512:
                case SignatureAlgorithm.ES512:
                    return SHA512.Create();
                default:
                    throw new ArgumentException("Invalid Algorithm", nameof(algorithm));
            }
        }

        public static string GetName(this SignatureAlgorithm algorithm)
        {
            switch(algorithm)
            {
                case SignatureAlgorithm.RS256:
                    return "RS256";
                case SignatureAlgorithm.RS384:
                    return "RS384";
                case SignatureAlgorithm.RS512:
                    return "RS512";
                case SignatureAlgorithm.PS256:
                    return "PS256";
                case SignatureAlgorithm.PS384:
                    return "PS384";
                case SignatureAlgorithm.PS512:
                    return "PS512";
                case SignatureAlgorithm.ES256:
                    return "ES256";
                case SignatureAlgorithm.ES384:
                    return "ES384";
                case SignatureAlgorithm.ES512:
                    return "ES512";
                case SignatureAlgorithm.ES256K:
                    return "ES256K";
                default:
                    return null;
            }
        }
    }
}
