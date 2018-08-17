// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Jwk;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net;
using IdentityModel.Internal;
using System.Linq;

namespace IdentityModel.Client
{
    /// <summary>
    /// Models the response from an OpenID Connect discovery endpoint
    /// </summary>
    public class DiscoveryResponse
    {
        /// <summary>
        /// Gets the raw response.
        /// </summary>
        /// <value>
        /// The raw.
        /// </value>
        public string Raw { get; }

        /// <summary>
        /// Gets the response as a JObject.
        /// </summary>
        /// <value>
        /// The json.
        /// </value>
        public JObject Json { get; }

        /// <summary>
        /// Gets a value indicating whether an error occurred.
        /// </summary>
        /// <value>
        ///   <c>true</c> if an error occurred; otherwise, <c>false</c>.
        /// </value>
        public bool IsError { get; } = false;

        /// <summary>
        /// Gets the status code.
        /// </summary>
        /// <value>
        /// The status code.
        /// </value>
        public HttpStatusCode StatusCode { get; }

        /// <summary>
        /// Gets the error.
        /// </summary>
        /// <value>
        /// The error.
        /// </value>
        public string Error { get; }

        /// <summary>
        /// Gets or sets the type of the error.
        /// </summary>
        /// <value>
        /// The type of the error.
        /// </value>
        public ResponseErrorType ErrorType { get; set; } = ResponseErrorType.None;

        /// <summary>
        /// Gets the exception.
        /// </summary>
        /// <value>
        /// The exception.
        /// </value>
        public Exception Exception { get; }

        /// <summary>
        /// Gets or sets the JSON web key set.
        /// </summary>
        /// <value>
        /// The key set.
        /// </value>
        public JsonWebKeySet KeySet { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DiscoveryResponse"/> class.
        /// </summary>
        /// <param name="raw">The raw response.</param>
        /// <param name="policy">The security policy.</param>
        public DiscoveryResponse(string raw, DiscoveryPolicy policy = null)
        {
            if (policy == null) policy = new DiscoveryPolicy();

            IsError = false;
            StatusCode = HttpStatusCode.OK;
            Raw = raw;

            try
            {
                Json = JObject.Parse(raw);
                var validationError = Validate(policy);

                if (validationError.IsPresent())
                {
                    IsError = true;
                    Json = null;

                    ErrorType = ResponseErrorType.PolicyViolation;
                    Error = validationError;
                }
            }
            catch (Exception ex)
            {
                IsError = true;

                ErrorType = ResponseErrorType.Exception;
                Error = ex.Message;
                Exception = ex;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DiscoveryResponse"/> class.
        /// </summary>
        /// <param name="statusCode">The status code.</param>
        /// <param name="reason">The reason.</param>
        public DiscoveryResponse(HttpStatusCode statusCode, string reason)
        {
            IsError = true;

            ErrorType = ResponseErrorType.Http;
            StatusCode = statusCode;
            Error = reason;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DiscoveryResponse" /> class.
        /// </summary>
        /// <param name="statusCode">The status code.</param>
        /// <param name="reason">The reason.</param>
        /// <param name="content">The content.</param>
        public DiscoveryResponse(HttpStatusCode statusCode, string reason, string content)
        {
            IsError = true;

            ErrorType = ResponseErrorType.Http;
            StatusCode = statusCode;
            Error = reason;
            Raw = content;

            try
            {
                Json = JObject.Parse(content);
            }
            catch { }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DiscoveryResponse"/> class.
        /// </summary>
        /// <param name="exception">The exception.</param>
        /// <param name="errorMessage">The error message.</param>
        public DiscoveryResponse(Exception exception, string errorMessage)
        {
            IsError = true;

            ErrorType = ResponseErrorType.Exception;
            Exception = exception;
            Error = $"{errorMessage}: {exception.Message}";
        }

        // strongly typed

        /// <summary>
        /// Gets the URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier. If Issuer discovery is supported (see Section 2), this value MUST be identical to the issuer value returned by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer..
        /// </summary>
        public string Issuer => TryGetString(OidcConstants.Discovery.Issuer);

        /// <summary>
        /// Gets the URL of the OP's OAuth 2.0 Authorization Endpoint.
        /// </summary>
        public string AuthorizeEndpoint => TryGetString(OidcConstants.Discovery.AuthorizationEndpoint);

        /// <summary>
        /// Gets the URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core]. This is REQUIRED unless only the Implicit Flow is used.
        /// </summary>
        public string TokenEndpoint => TryGetString(OidcConstants.Discovery.TokenEndpoint);

        /// <summary>
        /// Gets the URL of the OP's UserInfo Endpoint [OpenID.Core]. This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
        /// </summary>
        public string UserInfoEndpoint => TryGetString(OidcConstants.Discovery.UserInfoEndpoint);

        /// <summary>
        /// Gets the URL of the OP's OAuth 2.0 Introspection Endpoint.
        /// </summary>
        public string IntrospectionEndpoint => TryGetString(OidcConstants.Discovery.IntrospectionEndpoint);

        /// <summary>
        /// Gets the URL of the OP's OAuth 2.0 Revocation Endpoint.
        /// </summary>
        public string RevocationEndpoint => TryGetString(OidcConstants.Discovery.RevocationEndpoint);

        /// <summary>
        /// Gets the URL of the OP's OAuth 2.0 Device Authorization Endpoint.
        /// </summary>
        public string DeviceAuthorizationEndpoint => TryGetString(OidcConstants.Discovery.DeviceAuthorizationEndpoint);

        /// <summary>
        /// Gets the  URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage. Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
        /// </summary>
        public string JwksUri => TryGetString(OidcConstants.Discovery.JwksUri);

        /// <summary>
        /// Gets the URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP.
        /// </summary>
        public string EndSessionEndpoint => TryGetString(OidcConstants.Discovery.EndSessionEndpoint);

        /// <summary>
        /// Gets the URL of an OP iframe that supports cross-origin communications for session state information with the RP Client, using the HTML5 postMessage API. The page is loaded from an invisible iframe embedded in an RP page so that it can run in the OP's security context. It accepts postMessage requests from the relevant RP iframe and uses postMessage to post back the login status of the End-User at the OP.
        /// </summary>
        public string CheckSessionIframe => TryGetString(OidcConstants.Discovery.CheckSessionIframe);

        /// <summary>
        /// Gets the URL of the OP's Dynamic Client Registration Endpoint.
        /// </summary>
        public string RegistrationEndpoint => TryGetString(OidcConstants.Discovery.RegistrationEndpoint);

        /// <summary>
        /// Gets the value specifying whether the OP supports HTTP-based logout, with true indicating support. If omitted, the default value is false.
        /// </summary>
        public bool FrontChannelLogoutSupported => TryGetBoolean(OidcConstants.Discovery.FrontChannelLogoutSupported) ?? false;

        /// <summary>
        /// Gets the value specifying whether the OP can pass iss (issuer) and sid (session ID) query parameters to identify the RP session with the OP when the frontchannel_logout_uri is used. If supported, the sid Claim is also included in ID Tokens issued by the OP. If omitted, the default value is false.
        /// </summary>
        public bool FrontChannelLogoutSessionSupported => TryGetBoolean(OidcConstants.Discovery.FrontChannelLogoutSessionSupported) ?? false;

        /// <summary>
        /// Gets the value specifying whether the OP supports back-channel logout, with true indicating support. If omitted, the default value is false.
        /// </summary>
        public bool BackChannelLogoutSupported => TryGetBoolean(OidcConstants.Discovery.BackChannelLogoutSupported) ?? false;

        /// <summary>
        /// Gets the value specifying whether the OP can pass iss (issuer) and sid (session ID) query parameters to identify the RP session with the OP when the frontchannel_logout_uri is used. If supported, the sid Claim is also included in ID Tokens issued by the OP. If omitted, the default value is false.
        /// </summary>
        public bool BackChannelLogoutSessionSupported => TryGetBoolean(OidcConstants.Discovery.BackChannelLogoutSessionSupported) ?? false;

        /// <summary>
        /// Gets a list of the OAuth 2.0 Grant Type values that this OP supports. Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other Grant Types. If omitted, the default value is ["authorization_code", "implicit"].
        /// </summary>
        public IEnumerable<string> GrantTypesSupported => TryGetStringArray(OidcConstants.Discovery.GrantTypesSupported);

        /// <summary>
        /// Gets a list of PKCE [RFC7636] code challenge methods supported by this authorization server. Code challenge method values are used in the code_challenge_method parameter defined in Section 4.3 of [RFC7636]. The valid code challenge method values are those registered in the IANA "PKCE Code Challenge Methods" registry [IANA.OAuth.Parameters].
        /// </summary>
        public IEnumerable<string> CodeChallengeMethodsSupported => TryGetStringArray(OidcConstants.Discovery.CodeChallengeMethodsSupported);

        /// <summary>
        /// Gets a list of the OAuth 2.0 [RFC6749] scope values that this server supports. The server MUST support the openid scope value. Servers MAY choose not to advertise some supported scope values even when this parameter is used, although those defined in [OpenID.Core] SHOULD be listed, if supported.
        /// </summary>
        public IEnumerable<string> ScopesSupported => TryGetStringArray(OidcConstants.Discovery.ScopesSupported);

        /// <summary>
        /// Gets a list of the Subject Identifier types that this OP supports. Valid types include pairwise and public.
        /// </summary>
        public IEnumerable<string> SubjectTypesSupported => TryGetStringArray(OidcConstants.Discovery.SubjectTypesSupported);

        /// <summary>
        /// Gets a list of the OAuth 2.0 response_mode values that this OP supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses]. If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].
        /// </summary>
        public IEnumerable<string> ResponseModesSupported => TryGetStringArray(OidcConstants.Discovery.ResponseModesSupported);

        /// <summary>
        /// Gets a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.
        /// </summary>
        public IEnumerable<string> ResponseTypesSupported => TryGetStringArray(OidcConstants.Discovery.ResponseTypesSupported);

        /// <summary>
        /// Gets a list of the Claim Types that the OpenID Provider supports. These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core]. Values defined by this specification are normal, aggregated, and distributed. If omitted, the implementation supports only normal Claims.
        /// </summary>
        public IEnumerable<string> ClaimsSupported => TryGetStringArray(OidcConstants.Discovery.ClaimsSupported);

        /// <summary>
        /// Gets a list of Client Authentication methods supported by this Token Endpoint. The options are client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core]. Other authentication methods MAY be defined by extensions. If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
        /// </summary>
        public IEnumerable<string> TokenEndpointAuthenticationMethodsSupported => TryGetStringArray(OidcConstants.Discovery.TokenEndpointAuthenticationMethodsSupported);

        // generic

        /// <summary>
        /// Tries to get a JToken from the discovery document (or null).
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        public JToken TryGetValue(string name) => Json.TryGetValue(name);

        /// <summary>
        /// Tries to get a string from the discovery document (or null).
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        public string TryGetString(string name) => Json.TryGetString(name);

        /// <summary>
        /// Tries to get a boolean from the discovery document (or null).
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        public bool? TryGetBoolean(string name) => Json.TryGetBoolean(name);

        /// <summary>
        /// Tries to get a string array from the discovery document.
        /// </summary>
        /// <param name="name">The name.</param>
        /// <returns></returns>
        public IEnumerable<string> TryGetStringArray(string name) => Json.TryGetStringArray(name);

        private string Validate(DiscoveryPolicy policy)
        {
            if (policy.ValidateIssuerName)
            {
                if (string.IsNullOrWhiteSpace(Issuer)) return "Issuer name is missing";

                var isValid = ValidateIssuerName(Issuer.RemoveTrailingSlash(), policy.Authority.RemoveTrailingSlash(), policy.AuthorityNameComparison);
                if (!isValid) return "Issuer name does not match authority: " + Issuer;
            }

            var error = ValidateEndpoints(Json, policy);
            if (error.IsPresent()) return error;

            return string.Empty;
        }

        /// <summary>
        /// Checks if the issuer matches the authority.
        /// </summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="authority">The authority.</param>
        /// <returns></returns>
        public bool ValidateIssuerName(string issuer, string authority)
        {
            return ValidateIssuerName(issuer, authority, StringComparison.Ordinal);
        }

        /// <summary>
        /// Checks if the issuer matches the authority.
        /// </summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="authority">The authority.</param>
        /// <param name="nameComparison">The comparison mechanism that should be used when performing the match.</param>
        /// <returns></returns>
        public bool ValidateIssuerName(string issuer, string authority, StringComparison nameComparison)
        {
            return string.Equals(issuer, authority, nameComparison);
        }

        /// <summary>
        /// Validates the endoints and jwks_uri according to the security policy.
        /// </summary>
        /// <param name="json">The json.</param>
        /// <param name="policy">The policy.</param>
        /// <returns></returns>
        public string ValidateEndpoints(JObject json, DiscoveryPolicy policy)
        {
            // allowed hosts
            var allowedHosts = new HashSet<string>(policy.AdditionalEndpointBaseAddresses.Select(e => new Uri(e).Authority))
            {
                new Uri(policy.Authority).Authority
            };

            // allowed authorities (hosts + base address)
            var allowedAuthorities = new HashSet<string>(policy.AdditionalEndpointBaseAddresses)
            {
                policy.Authority
            };

            foreach (var element in json)
            {
                if (element.Key.EndsWith("endpoint", StringComparison.OrdinalIgnoreCase) ||
                    element.Key.Equals(OidcConstants.Discovery.JwksUri, StringComparison.OrdinalIgnoreCase) ||
                    element.Key.Equals(OidcConstants.Discovery.CheckSessionIframe, StringComparison.OrdinalIgnoreCase))
                {
                    var endpoint = element.Value.ToString();

                    var isValidUri = Uri.TryCreate(endpoint, UriKind.Absolute, out Uri uri);
                    if (!isValidUri)
                    {
                        return $"Malformed endpoint: {endpoint}";
                    }

                    if (!DiscoveryEndpoint.IsValidScheme(uri))
                    {
                        return $"Malformed endpoint: {endpoint}";
                    }

                    if (!DiscoveryEndpoint.IsSecureScheme(uri, policy))
                    {
                        return $"Endpoint does not use HTTPS: {endpoint}";
                    }

                    if (policy.ValidateEndpoints)
                    {
                        // if endpoint is on exclude list, don't validate
                        if (policy.EndpointValidationExcludeList.Contains(element.Key)) continue;

                        bool isAllowed = false;
                        foreach (var host in allowedHosts)
                        {
                            if (string.Equals(host, uri.Authority))
                            {
                                isAllowed = true;
                            }
                        }

                        if (!isAllowed)
                        {
                            return $"Endpoint is on a different host than authority: {endpoint}";
                        }


                        isAllowed = false;
                        foreach (var authority in allowedAuthorities)
                        {
                            if (endpoint.StartsWith(authority, policy.AuthorityNameComparison))
                            {
                                isAllowed = true;
                            }
                        }

                        if (!isAllowed)
                        {
                            return $"Endpoint belongs to different authority: {endpoint}";
                        }
                    }
                }
            }

            if (policy.RequireKeySet)
            {
                if (string.IsNullOrWhiteSpace(JwksUri))
                {
                    return "Keyset is missing";
                }
            }

            return string.Empty;
        }
    }
}