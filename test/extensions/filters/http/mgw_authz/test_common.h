#pragma once

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MgwAuthz {

// A good config.
const char MgwAuthzExampleConfig[] = R"(
rules:
- match:
    prefix: "/path"
  scopes: "scope1 scope2"
)";

const char MgwAuthzExampleWrongScopeConfig[] = R"(
rules:
- match:
    prefix: "/path"
  scopes: "scope2"
)";

// A good public key
// wso2 apim 3.1.0 public key
const char PublicKey[] = R"(
{
	"keys": [{
		"kty": "RSA",
		"n": "xeqoZYbQ_Sr8DOFQ-_qbEbCp6Vzb5hzH7oa3hf2FZxRKF0H6b8COMzz8-0mvEdYVvb_31jMEL2CIQhkQRol1IruD6nBOmkjuXJSBficklMaJZORhuCrB4roHxzoG19aWmscA0gnfBKo2oGXSjJmnZxIh-2X6syHCfyMZZ00LzDyrgoXWQXyFvCA2ax54s7sKiHOM3P4A9W4QUwmoEi4HQmPgJjIM4eGVPh0GtIANN-BOQ1KkUI7OzteHCTLu3VjxM0sw8QRayZdhniPF-U9n3fa1mO4KLBsW4mDLjg8R_JuAGTX_SEEGj0B5HWQAP6myxKFz2xwDaCGvT-rdvkktOw",
		"e": "AQAB"
	}]
}
)";

// A good config.
const char ExampleConfig[] = R"(
providers:
  example_provider:
    forward_payload_header: jwt-payload
    issuer: https://localhost:9443/oauth2/token
    audiences:
    - http://org.wso2.apimgt/gateway
    remote_jwks:
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster
    payload_in_metadata: jwt-payload
rules:
- match:
    path: "/path"
  requires:
    provider_name: "example_provider"
)";

// The name of provider for above config.
const char ProviderName[] = "example_provider";

// Payload:
// with scopes "scope": "am_application_scope scope1"
const char GoodToken[] =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5UZG1aak00WkRrM05qWTBZemM1TW1abU9EZ3dNVEUzTVdZd0"
    "5ERTVNV1JsWkRnNE56YzRaQT09In0."
    "eyJhdWQiOiJodHRwOlwvXC9vcmcud3NvMi5hcGltZ3RcL2dhdGV3YXkiLCJzdWIiOiJhZG1pbkBjYXJib24uc3VwZXIiLC"
    "JhcHBsaWNhdGlvbiI6eyJvd25lciI6ImFkbWluIiwidGllclF1b3RhVHlwZSI6InJlcXVlc3RDb3VudCIsInRpZXIiOiJV"
    "bmxpbWl0ZWQiLCJuYW1lIjoiRGVmYXVsdEFwcGxpY2F0aW9uIiwiaWQiOjEsInV1aWQiOm51bGx9LCJzY29wZSI6ImFtX2"
    "FwcGxpY2F0aW9uX3Njb3BlIHNjb3BlMSIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tl"
    "biIsInRpZXJJbmZvIjp7IlVubGltaXRlZCI6eyJ0aWVyUXVvdGFUeXBlIjoicmVxdWVzdENvdW50Iiwic3RvcE9uUXVvdG"
    "FSZWFjaCI6dHJ1ZSwic3Bpa2VBcnJlc3RMaW1pdCI6MCwic3Bpa2VBcnJlc3RVbml0IjpudWxsfX0sImtleXR5cGUiOiJQ"
    "Uk9EVUNUSU9OIiwic3Vic2NyaWJlZEFQSXMiOlt7InN1YnNjcmliZXJUZW5hbnREb21haW4iOiJjYXJib24uc3VwZXIiLC"
    "JuYW1lIjoiUGl6emFTaGFja0FQSSIsImNvbnRleHQiOiJcL3Bpenphc2hhY2tcLzEuMC4wIiwicHVibGlzaGVyIjoiYWRt"
    "aW4iLCJ2ZXJzaW9uIjoiMS4wLjAiLCJzdWJzY3JpcHRpb25UaWVyIjoiVW5saW1pdGVkIn1dLCJjb25zdW1lcktleSI6Im"
    "h1bURHb211amdnZGQ1a21BSlFreHJmaUxEZ2EiLCJleHAiOjM3NDEyMzg0MTcsImlhdCI6MTU5Mzc1NDc3MCwianRpIjoi"
    "YjkzYTA0NzctYjFkNS00ZTI2LWE3NTItNTY1ODFlZTg2ZmYxIn0.mnJDcIaHUB6Ny_nLhRZTcE3M2i_pQGcwPpiGkqi__"
    "lZqO-gyEPEWGSAgE757rR834ftR1nMkTj_mHfnfwZNOfxj0Xr-sfENLiGH0YvR9Q-"
    "ddRLDraGDijk50PL5xWzgixJgKWSp0sNjJxdN37l8o16bH4bJxcj_hKmUgg-H-Oq8tiPRHh_MXou2smDUezMXzgv-"
    "PvkHF_-CM6qPtszd9Htnw3_2wcZ3-1XReeJM1CjgkW-FjwZZssAHAGMefEMdszmLX4P0g5akgr_DFHwr1aDtW6_"
    "IGdn5klD3VcSKYLyjuud1Ax0y0NWQYlQJAXM7pdHzALEfrLCAOB5Z37iXwTA";




// const char ExampleConfig[] = R"(
// providers:
//   example_provider:
//     issuer: https://example.com
//     audiences:
//     - example_service
//     - http://example_service1
//     - https://example_service2/
//     remote_jwks:
//       http_uri:
//         uri: https://pubkey_server/pubkey_path
//         cluster: pubkey_cluster
//         timeout:
//           seconds: 5
//       cache_duration:
//         seconds: 600
//     forward_payload_header: sec-istio-auth-userinfo
// rules:
// - match:
//     path: "/"
//   requires:
//     provider_name: "example_provider"
// bypass_cors_preflight: true
// )";

// const char GoodToken[] = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUu"
//                          "Y29tIiwic3ViIjoidGVzdEBleGFtcGxlLmNvbSIsImV4cCI6MjAwMTAwMTAwMSwiY"
//                          "XVkIjoiZXhhbXBsZV9zZXJ2aWNlIn0.cuui_Syud76B0tqvjESE8IZbX7vzG6xA-M"
//                          "Daof1qEFNIoCFT_YQPkseLSUSR2Od3TJcNKk-dKjvUEL1JW3kGnyC1dBx4f3-Xxro"
//                          "yL23UbR2eS8TuxO9ZcNCGkjfvH5O4mDb6cVkFHRDEolGhA7XwNiuVgkGJ5Wkrvshi"
//                          "h6nqKXcPNaRx9lOaRWg2PkE6ySNoyju7rNfunXYtVxPuUIkl0KMq3WXWRb_cb8a_Z"
//                          "EprqSZUzi_ZzzYzqBNVhIJujcNWij7JRra2sXXiSAfKjtxHQoxrX8n4V1ySWJ3_1T"
//                          "H_cJcdfS_RKP7YgXRWC0L16PNF5K7iqRqmjKALNe83ZFnFIw";

// const char PublicKey[] = R"(
// {
//   "keys": [
//     {
//       "kty": "RSA",
//       "alg": "RS256",
//       "use": "sig",
//       "kid": "62a93512c9ee4c7f8067b5a216dade2763d32a47",
//       "n": "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
//       "e": "AQAB"
//     },
//     {
//       "kty": "RSA",
//       "alg": "RS256",
//       "use": "sig",
//       "kid": "b3319a147514df7ee5e4bcdee51350cc890cc89e",
//       "n": "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
//       "e": "AQAB"
//     }
//   ]
// }
// )";

const char ExpectedPayloadValue[] = "eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoidGVzdEBleGFtcG"
                                    "xlLmNvbSIsImV4cCI6MjAwMTAwMTAwMSwiYXVkIjoiZXhhbXBsZV9zZXJ2"
                                    "aWNlIn0";

} // namespace JwtAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
