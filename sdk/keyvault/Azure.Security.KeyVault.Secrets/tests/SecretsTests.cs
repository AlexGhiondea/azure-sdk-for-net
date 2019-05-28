using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Azure.Security.KeyVault.Secrets;
using NUnit.Framework;
using Azure.Identity;

namespace Azure.Security.KeyVault.Test
{
    public class SecretTests : KeyVaultTestBase
    {
        //private static string s_tenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        //private static string s_clientId = "20b5a4f5-a68a-4ee3-b6d9-7d153e2899df";
        //private static string s_clientSecret = "1:[a@RS]R9sy1OfzcJ8oCJO6j+GMoX9[";


        static void Main(string[] args)
        {

        }
        public SecretTests()
        {
        }

        [Test]
        public async Task CredentialProvider()
        {
            var client = new Secrets.SecretClient(VaultUri, AzureCredential.Default);

            Secret setResult = await client.SetAsync("CrudBasic", "CrudBasicValue1");

            Secret getResult = await client.GetAsync("CrudBasic");

            AssertSecretsEqual(setResult, getResult);

            DeletedSecret deleteResult = await client.DeleteAsync("CrudBasic");

            //HACK: AssertSecretsEqual(setResult, deleteResult);
        }

        [Test]
        public async Task CrudBasic()
        {
            var client = new SecretClient(VaultUri, AzureCredential.Default);

            Secret setResult = await client.SetAsync("CrudBasic", "CrudBasicValue1");

            Secret getResult = await client.GetAsync("CrudBasic");

            Assert.Equals("CrudBasic", setResult.Name);
            Assert.Equals(VaultUri, setResult.Vault);

            AssertSecretsEqual(setResult, getResult);

            getResult.Enabled = false;
            SecretBase updateResult = await client.UpdateAsync(getResult);

            AssertSecretsEqual(getResult, updateResult);

            DeletedSecret deleteResult = await client.DeleteAsync("CrudBasic");

            //HACKL AssertSecretsEqual(updateResult, deleteResult);
        }

        [Test]
        public async Task CrudWithExtendedProps()
        {
            var client = new SecretClient(VaultUri, AzureCredential.Default);

            var secret = new Secret("CrudWithExtendedProps", "CrudWithExtendedPropsValue1")
            {
                ContentType = "password",
                NotBefore = UtcNowMs() + TimeSpan.FromDays(1),
                Expires = UtcNowMs() + TimeSpan.FromDays(90)
            };

            Secret setResult = await client.SetAsync(secret);

            Assert.Equals("password", setResult.ContentType);

            Secret getResult = await client.GetAsync("CrudWithExtendedProps");

            AssertSecretsEqual(setResult, getResult);

            DeletedSecret deleteResult = await client.DeleteAsync("CrudWithExtendedProps");

            // remove the value which is not set on the deleted response
            typeof(Secret).GetProperty(nameof(setResult.Value)).SetValue(setResult, null);

            //HACK AssertSecretsEqual(setResult, deleteResult);
        }

        [Test]
        public async Task BackupRestore()
        {
            var backupPath = Path.GetTempFileName();

            try
            {
                var client = new SecretClient(VaultUri, AzureCredential.Default);

                Secret setResult = await client.SetAsync("BackupRestore", "BackupRestore");

                //await File.WriteAllBytesAsync(backupPath, await client.BackupAsync("BackupRestore"));

                await client.DeleteAsync("BackupRestore");

               // Secret restoreResult = await client.RestoreAsync(await File.ReadAllBytesAsync(backupPath));

                // remove the vaule which is not set in the restore response
                typeof(Secret).GetProperty(nameof(setResult.Value)).SetValue(setResult, null);

                //AssertSecretsEqual(setResult, restoreResult);
            }
            finally
            {
                File.Delete(backupPath);
            }
        }

        private DateTime UtcNowMs()
        {
            return DateTime.MinValue.ToUniversalTime() + TimeSpan.FromMilliseconds(new TimeSpan(DateTime.UtcNow.Ticks).TotalMilliseconds);
        }

    }

    public class SecretListTests : KeyVaultTestBase, IDisposable
    {
        private const int VersionCount = 50;
        private readonly string SecretName = Guid.NewGuid().ToString("N");

        private readonly Dictionary<string, Secret> _versions = new Dictionary<string, Secret>(VersionCount);
        private readonly SecretClient _client;

        public SecretListTests()
        {
            _client = new SecretClient(VaultUri, AzureCredential.Default);

            for (int i = 0; i < VersionCount; i++)
            {
                Secret secret = _client.SetAsync(SecretName, Guid.NewGuid().ToString("N")).GetAwaiter().GetResult();

                typeof(Secret).GetProperty(nameof(secret.Value)).SetValue(secret, null);

                _versions[secret.Id.ToString()] = secret;
            }
        }

        public void Dispose()
        {
            var deleteResult = _client.DeleteAsync(SecretName);
        }

        [Test]
        public async Task GetAllVersionsAsyncForEach()
        {
            int actVersionCount = 0;

            await foreach (var secret in _client.GetAllVersionsAsync(SecretName))
            {
                Assert.True(_versions.TryGetValue(secret.Id.ToString(), out Secret exp));

                AssertSecretsEqual(exp, secret);

                actVersionCount++;
            }

            Assert.Equals(VersionCount, actVersionCount);
        }

        [Test]
        public async Task ListVersionEnumeratorMoveNext()
        {
            int actVersionCount = 0;

            var enumerator = _client.GetAllVersionsAsync(SecretName);

            while (await enumerator.MoveNextAsync())
            {
                Assert.True(_versions.TryGetValue(enumerator.Current.Id.ToString(), out Secret exp));

                AssertSecretsEqual(exp, enumerator.Current);

                actVersionCount++;
            }

            Assert.Equals(VersionCount, actVersionCount);
        }


        [Test]
        public async Task GetAllVersionsByPageAsyncForEach()
        {
            int actVersionCount = 0;

            await foreach (Page<SecretBase> currentPage in _client.GetAllVersionsAsync(SecretName).ByPage())
            {
                for (int i = 0; i < currentPage.Items.Length; i++)
                {
                    Assert.True(_versions.TryGetValue(currentPage.Items[i].Id.ToString(), out Secret exp));

                    AssertSecretsEqual(exp, currentPage.Items[i]);

                    actVersionCount++;
                }
            }

            Assert.Equals(VersionCount, actVersionCount);
        }

        [Test]
        public async Task ListVersionByPageEnumeratorMoveNext()
        {
            int actVersionCount = 0;

            var enumerator = _client.GetAllVersionsAsync(SecretName).ByPage();

            while (await enumerator.MoveNextAsync())
            {
                Page<SecretBase> currentPage = enumerator.Current;

                Assert.True(currentPage.Items.Length <= 5);

                for (int i = 0; i < currentPage.Items.Length; i++)
                {
                    Assert.True(_versions.TryGetValue(currentPage.Items[i].Id.ToString(), out Secret exp));

                    AssertSecretsEqual(exp, currentPage.Items[i]);

                    actVersionCount++;
                }
            }

            Assert.Equals(VersionCount, actVersionCount);
        }
    }

    public class KeyVaultTestBase
    {

        //protected class MockMsalCredentialProvider : ITokenCredentialProvider
        //{
        //    public async Task<ITokenCredential> GetCredentialAsync(IEnumerable<string> scopes = null, CancellationToken cancellation = default)
        //    {
        //        var resource = scopes?.FirstOrDefault()?.Replace("/.Default", string.Empty);

        //        return await TokenCredential.CreateCredentialAsync(async (cancel) => { return await this.RefreshToken(resource, cancel); });
        //    }

        //    private async Task<TokenRefreshResult> RefreshToken(string resource, CancellationToken cancellation)
        //    {
        //        var authResult = await s_authContext.Value.AcquireTokenAsync(resource, s_clientCredential.Value);

        //        return new TokenRefreshResult() { Delay = authResult.ExpiresOn.AddMinutes(-5) - DateTime.UtcNow, Token = authResult.AccessToken };
        //    }
        //}

        //private static Lazy<string> s_tenantId = new Lazy<string>(() => { return Environment.GetEnvironmentVariable("AZURE_TENANT_ID"); });

        //private static Lazy<string> s_clientId = new Lazy<string>(() => { return Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"); });

        //private static Lazy<string> s_clientSecret = new Lazy<string>(() => { return Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET"); });

        //private static Lazy<ClientCredential> s_clientCredential = new Lazy<ClientCredential>(() => { return new ClientCredential(s_clientId.Value, s_clientSecret.Value); });

        //private static Lazy<AuthenticationContext> s_authContext = new Lazy<AuthenticationContext>(() => { return new AuthenticationContext("https://login.microsoftonline.com/" + s_tenantId.Value); });

        //private static Lazy<TokenCredential> s_credential = new Lazy<TokenCredential>(() => { return TokenCredential.CreateCredentialAsync(RefreshTokenWithAuthContext).GetAwaiter().GetResult(); });

        private static Lazy<Uri> s_vaultUri = new Lazy<Uri>(() => { return new Uri("https://net-keyvault.vault.azure.net/"); });

        //protected TokenCredential TestCredential { get => s_credential.Value; }

        protected Uri VaultUri { get => s_vaultUri.Value; }

        //private static async Task<TokenRefreshResult> RefreshTokenWithAuthContext(CancellationToken cancellation)
        //{
        //    var authResult = await s_authContext.Value.AcquireTokenAsync("https://vault.azure.net", s_clientCredential.Value);

        //    return new TokenRefreshResult() { Delay = authResult.ExpiresOn.AddMinutes(-5) - DateTime.UtcNow, Token = authResult.AccessToken };
        //}

        protected void AssertSecretsEqual(Secret exp, Secret act)
        {
            Assert.Equals(exp.Value, act.Value);

        }

        protected void AssertSecretsEqual(SecretBase exp, SecretBase act)
        {
            Assert.Equals(exp.Id, act.Id);
            Assert.Equals(exp.ContentType, act.ContentType);
            Assert.Equals(exp.KeyId, act.KeyId);
            Assert.Equals(exp.Managed, act.Managed);

            Assert.Equals(exp.Enabled, act.Enabled);
            Assert.Equals(exp.Expires, act.Expires);
            Assert.Equals(exp.NotBefore, act.NotBefore);
        }
    }
}