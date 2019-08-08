using Azure.Core;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Azure.Security.KeyVault.Keys.Cryptography
{
    /// <summary>
    /// 
    /// </summary>
    public class CryptographicKey : IDisposable
    {
        private SemaphoreSlim _initLock = new SemaphoreSlim(1, 1);
        private JsonWebKey _key;
        private Uri _keyId;
        private ICryptographyProvider _cryptoProvider;

        /// <summary>
        /// Protected cosntructor for mocking
        /// </summary>
        protected CryptographicKey()
        {

        }

        public CryptographicKey(CryptographyClient client)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyId"></param>
        /// <param name="credential"></param>
        /// <param name="options"></param>
        public CryptographicKey(Uri keyId, TokenCredential credential, CryptographyClientOptions options)
        {
            _keyId = keyId ?? throw new ArgumentNullException(nameof(keyId));

            _cryptoProvider = new CryptographyClient(keyId, credential);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <param name="credential"></param>
        internal CryptographicKey(JsonWebKey key, TokenCredential credential)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <param name="credential"></param>
        /// <param name="options"></param>
        internal CryptographicKey(JsonWebKey key, TokenCredential credential, CryptographyClientOptions options)
        {

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="plaintext"></param>
        /// <param name="iv"></param>
        /// <param name="authenticationData"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<EncryptResult> EncryptAsync(EncryptionAlgorithm algorithm, byte[] plaintext, byte[] iv = default, byte[] authenticationData = default, CancellationToken cancellationToken = default)
        {
            return await _cryptoProvider.EncryptAsync(algorithm, plaintext, iv, authenticationData, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="plaintext"></param>
        /// <param name="iv"></param>
        /// <param name="authenticationData"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual EncryptResult Encrypt(EncryptionAlgorithm algorithm, byte[] plaintext, byte[] iv = default, byte[] authenticationData = default, CancellationToken cancellationToken = default)
        {
            return _cryptoProvider.Encrypt(algorithm, plaintext, iv, authenticationData, cancellationToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="ciphertext"></param>
        /// <param name="iv"></param>
        /// <param name="authenticationData"></param>
        /// <param name="authenticationTag"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<DecryptResult> DecryptAsync(EncryptionAlgorithm algorithm, byte[] ciphertext, byte[] iv = default, byte[] authenticationData = default, byte[] authenticationTag = default, CancellationToken cancellationToken = default)
        {
            return await _cryptoProvider.DecryptAsync(algorithm, ciphertext, iv, authenticationData, authenticationTag, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="ciphertext"></param>
        /// <param name="iv"></param>
        /// <param name="authenticationData"></param>
        /// <param name="authenticationTag"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual DecryptResult Decrypt(EncryptionAlgorithm algorithm, byte[] ciphertext, byte[] iv = default, byte[] authenticationData = default, byte[] authenticationTag = default, CancellationToken cancellationToken = default)
        {
            return _cryptoProvider.Decrypt(algorithm, ciphertext, iv, authenticationData, authenticationTag, cancellationToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="key"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<WrapResult> WrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] key, CancellationToken cancellationToken = default)
        {
            return await _cryptoProvider.WrapKeyAsync(algorithm, key, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="key"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual WrapResult WrapKey(KeyWrapAlgorithm algorithm, byte[] key, CancellationToken cancellationToken = default)
        {
            return _cryptoProvider.WrapKey(algorithm, key, cancellationToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="encryptedKey"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<UnwrapResult> UnwrapKeyAsync(KeyWrapAlgorithm algorithm, byte[] encryptedKey, CancellationToken cancellationToken = default)
        {
            return await _cryptoProvider.UnwrapKeyAsync(algorithm, encryptedKey, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="encryptedKey"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual UnwrapResult UnwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey, CancellationToken cancellationToken = default)
        {
            return _cryptoProvider.UnwrapKey(algorithm, encryptedKey, cancellationToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="digest"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<SignResult> SignAsync(SignatureAlgorithm algorithm, byte[] digest, CancellationToken cancellationToken = default)
        {
            return await _cryptoProvider.SignAsync(algorithm, digest, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="digest"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual SignResult Sign(SignatureAlgorithm algorithm, byte[] digest, CancellationToken cancellationToken = default)
        {
            return _cryptoProvider.Sign(algorithm, digest, cancellationToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="digest"></param>
        /// <param name="signature"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<VerifyResult> VerifyAsync(SignatureAlgorithm algorithm, byte[] digest, byte[] signature, CancellationToken cancellationToken = default)
        {
            return await _cryptoProvider.VerifyAsync(algorithm, digest, signature, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="digest"></param>
        /// <param name="signature"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual VerifyResult Verify(SignatureAlgorithm algorithm, byte[] digest, byte[] signature, CancellationToken cancellationToken = default)
        {
            return _cryptoProvider.Verify(algorithm, digest, signature, cancellationToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="data"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<SignResult> SignDataAsync(SignatureAlgorithm algorithm, byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            byte[] digest = CreateDigest(algorithm, data);

            return await _cryptoProvider.SignAsync(algorithm, digest, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="data"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual SignResult SignData(SignatureAlgorithm algorithm, byte[] data, CancellationToken cancellationToken = default)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            byte[] digest = CreateDigest(algorithm, data);

            return _cryptoProvider.Sign(algorithm, digest, cancellationToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="data"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<SignResult> SignDataAsync(SignatureAlgorithm algorithm, Stream data, CancellationToken cancellationToken = default)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            byte[] digest = CreateDigest(algorithm, data);

            return await _cryptoProvider.SignAsync(algorithm, digest, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="data"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual SignResult SignData(SignatureAlgorithm algorithm, Stream data, CancellationToken cancellationToken = default)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            byte[] digest = CreateDigest(algorithm, data);

            return _cryptoProvider.Sign(algorithm, digest, cancellationToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<VerifyResult> VerifyDataAsync(SignatureAlgorithm algorithm, byte[] data, byte[] signature, CancellationToken cancellationToken = default)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            byte[] digest = CreateDigest(algorithm, data);

            return await _cryptoProvider.VerifyAsync(algorithm, digest, signature, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual VerifyResult VerifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature, CancellationToken cancellationToken = default)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            byte[] digest = CreateDigest(algorithm, data);

            return _cryptoProvider.Verify(algorithm, digest, signature, cancellationToken);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual async Task<VerifyResult> VerifyDataAsync(SignatureAlgorithm algorithm, Stream data, byte[] signature, CancellationToken cancellationToken = default)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            byte[] digest = CreateDigest(algorithm, data);

            return await _cryptoProvider.VerifyAsync(algorithm, digest, signature, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public virtual VerifyResult VerifyData(SignatureAlgorithm algorithm, Stream data, byte[] signature, CancellationToken cancellationToken = default)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            byte[] digest = CreateDigest(algorithm, data);

            return _cryptoProvider.Verify(algorithm, digest, signature, cancellationToken);
        }

        /// <summary>
        /// Disposes the CryptographicKey
        /// </summary>
        public void Dispose()
        {
            if (_initLock != null)
            {
                _initLock.Dispose();
            }

            GC.SuppressFinalize(this);
        }

        private byte[] CreateDigest(SignatureAlgorithm algorithm, byte[] data)
        {
            using(HashAlgorithm hashAlgo = algorithm.GetHashAlgorithm())
            {
                return hashAlgo.ComputeHash(data);
            }
        }

        private byte[] CreateDigest(SignatureAlgorithm algorithm, Stream data)
        {
            using (HashAlgorithm hashAlgo = algorithm.GetHashAlgorithm())
            {
                return hashAlgo.ComputeHash(data);
            }
        }

    }
}
