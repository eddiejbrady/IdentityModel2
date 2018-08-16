using FluentAssertions;
using IdentityModel.Client;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace IdentityModel.UnitTests
{
    public class DiscoveryCacheTests
    {
        readonly NetworkHandler _successHandler;
        readonly string _authority = "https://demo.identityserver.io";

        public DiscoveryCacheTests()
        {
            var discoFileName = FileName.Create("discovery.json");
            var document = File.ReadAllText(discoFileName);

            var jwksFileName = FileName.Create("discovery_jwks.json");
            var jwks = File.ReadAllText(jwksFileName);

            _successHandler = new NetworkHandler(request =>
            {
                if (request.RequestUri.AbsoluteUri.EndsWith("jwks"))
                {
                    return jwks;
                }

                return document;
            }, HttpStatusCode.OK);
        }

        [Fact]
        public async Task Implicit_client_should_work()
        {
            var client = new HttpClient(_successHandler);
            var cache = new DiscoveryCache(_authority);

            var disco = await cache.GetAsync();

            disco.IsError.Should().BeFalse();
        }

        [Fact]
        public async Task Explicit_client_should_work()
        {
            var client = new HttpClient(_successHandler);
            var cache = new DiscoveryCache(_authority, () => new HttpClient());

            var disco = await cache.GetAsync();

            disco.IsError.Should().BeFalse();
        }
    }
}
