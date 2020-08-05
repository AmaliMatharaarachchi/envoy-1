#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/extensions/filters/http/mgw_authz/v3/mgw_authz.pb.h"
#include "envoy/extensions/filters/http/jwt_authn/v3/config.pb.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"

#include "common/router/string_accessor_impl.h"

#include "extensions/filters/http/common/pass_through_filter.h"
#include "extensions/filters/http/well_known_names.h"

#include "test/extensions/filters/http/common/empty_http_filter_config.h"
#include "test/extensions/filters/http/mgw_authz/test_common.h"
#include "test/integration/http_protocol_integration.h"

using envoy::extensions::filters::http::mgw_authz::v3::MgwAuthz;
using envoy::extensions::filters::network::http_connection_manager::v3::HttpFilter;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MgwAuthz {
namespace {

using MgwAuthzIntegrationTest = HttpProtocolIntegrationTest;
INSTANTIATE_TEST_SUITE_P(Protocols, MgwAuthzIntegrationTest,
                         testing::ValuesIn(HttpProtocolIntegrationTest::getProtocolTestParams()),
                         HttpProtocolIntegrationTest::protocolTestParamsToString);

std::string getAuthFilterConfig(const std::string& jwt_authn_config_str) {
  envoy::extensions::filters::http::jwt_authn::v3::JwtAuthentication jwt_authn_proto_config;
  TestUtility::loadFromYaml(jwt_authn_config_str, jwt_authn_proto_config);
  auto& provider0 = (*jwt_authn_proto_config.mutable_providers())[std::string(ProviderName)];
  provider0.clear_remote_jwks();
  auto local_jwks = provider0.mutable_local_jwks();
  local_jwks->set_inline_string(PublicKey);
  HttpFilter filter;
  filter.set_name(HttpFilterNames::get().JwtAuthn);
  filter.mutable_typed_config()->PackFrom(jwt_authn_proto_config);
  return MessageUtil::getJsonStringFromMessage(filter);
}

// This tests the scope validation is passed, in the happy path
// for "scope1 or scope2" enabled for /path,
// provided jwt has scope1 and am_application_scope. Since it has scope1, this request should be authorized.
TEST_P(MgwAuthzIntegrationTest, WithScopeGoodToken) {
  envoy::extensions::filters::http::mgw_authz::v3::MgwAuthz mgw_authz_proto_config;
  TestUtility::loadFromYaml(MgwAuthzExampleConfig, mgw_authz_proto_config);
  HttpFilter filter;
  filter.set_name(HttpFilterNames::get().MgwAuthorization);
  filter.mutable_typed_config()->PackFrom(mgw_authz_proto_config);
  config_helper_.addFilter(MessageUtil::getJsonStringFromMessage(filter));
  config_helper_.addFilter(getAuthFilterConfig(ExampleConfig));

  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  auto response = codec_client_->makeHeaderOnlyRequest(Http::TestRequestHeaderMapImpl{
      {":method", "GET"},
      {":path", "/path"},
      {":scheme", "http"},
      {":authority", "host"},
      {"Authorization", "Bearer " + std::string(GoodToken)},
  });
  waitForNextUpstreamRequest();
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);
  response->waitForEndStream();

  ASSERT_TRUE(response->complete());
  EXPECT_EQ("200", response->headers().Status()->value().getStringView());
}

// This tests the scope validation is passed, in the happy path
// for "scope2" enabled for path /,
// provided jwt has only scope1, so authorization should fail.
TEST_P(MgwAuthzIntegrationTest, WithoutScopeGoodToken) {

  // Add filter configs.
  envoy::extensions::filters::http::mgw_authz::v3::MgwAuthz mgw_authz_proto_config;
  TestUtility::loadFromYaml(MgwAuthzExampleWrongScopeConfig, mgw_authz_proto_config);
  HttpFilter filter;
  filter.set_name(HttpFilterNames::get().MgwAuthorization);
  filter.mutable_typed_config()->PackFrom(mgw_authz_proto_config);
  config_helper_.addFilter(MessageUtil::getJsonStringFromMessage(filter));
  config_helper_.addFilter(getAuthFilterConfig(ExampleConfig));

  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  auto response = codec_client_->makeHeaderOnlyRequest(Http::TestRequestHeaderMapImpl{
      {":method", "GET"},
      {":path", "/path"},
      {":scheme", "http"},
      {":authority", "host"},
      {"Authorization", "Bearer " + std::string(GoodToken)},
  });
  response->waitForEndStream();

  ASSERT_TRUE(response->complete());
  EXPECT_EQ("403", response->headers().Status()->value().getStringView());
}

// This tests the scope validation is passed, when scope validation is not enabled for the path
// for "scope2" enabled only for /path,
// Since scope validation has not enabled for /user, this request should be authorized.
TEST_P(MgwAuthzIntegrationTest, NoScopePath) {
  envoy::extensions::filters::http::mgw_authz::v3::MgwAuthz mgw_authz_proto_config;
  TestUtility::loadFromYaml(MgwAuthzExampleWrongScopeConfig, mgw_authz_proto_config);
  HttpFilter filter;
  filter.set_name(HttpFilterNames::get().MgwAuthorization);
  filter.mutable_typed_config()->PackFrom(mgw_authz_proto_config);
  config_helper_.addFilter(MessageUtil::getJsonStringFromMessage(filter));
  config_helper_.addFilter(getAuthFilterConfig(ExampleConfig));

  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  auto response = codec_client_->makeHeaderOnlyRequest(Http::TestRequestHeaderMapImpl{
      {":method", "GET"},
      {":path", "/user"},
      {":scheme", "http"},
      {":authority", "host"},
      {"Authorization", "Bearer " + std::string(GoodToken)},
  });
  waitForNextUpstreamRequest();
  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);
  response->waitForEndStream();

  ASSERT_TRUE(response->complete());
  EXPECT_EQ("200", response->headers().Status()->value().getStringView());
}

} // namespace
} // namespace MgwAuthz
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
