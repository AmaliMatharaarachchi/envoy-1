#include "extensions/filters/http/mgw_pre_authn/config.h"

#include <chrono>
#include <string>

// #include "envoy/config/core/v3/grpc_service.pb.h"
#include "envoy/extensions/filters/http/mgw_pre_authn/v3/mgw_pre_authn.pb.h"
#include "envoy/extensions/filters/http/mgw_pre_authn/v3/mgw_pre_authn.pb.validate.h"
#include "envoy/registry/registry.h"

#include "common/protobuf/utility.h"

#include "extensions/filters/http/mgw_pre_authn/mgw_pre_authn.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MgwPreAuthn {

Http::FilterFactoryCb MgwPreAuthnFilterConfig::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::mgw_pre_authn::v3::MgwPreAuthn& proto_config,
    const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {
  const auto filter_config =
      std::make_shared<FilterConfig>(proto_config, context.localInfo(), context.scope(),
                                     context.runtime(), context.httpContext(), stats_prefix);
  Http::FilterFactoryCb callback;
  callback = [filter_config](
                  Http::FilterChainFactoryCallbacks& callbacks) {
    callbacks.addStreamDecoderFilter(Http::StreamDecoderFilterSharedPtr{
        std::make_shared<Filter>(filter_config)});
  };

  std::cout << "mgw create filter pre_authn" << std::endl;
  // std::cout << callback << std::endl;

  return callback;
};

/**
 * Static registration for the mgw authorization filter. @see RegisterFactory.
 */
REGISTER_FACTORY(MgwPreAuthnFilterConfig,
                 Server::Configuration::NamedHttpFilterConfigFactory){"envoy.mgw_pre_authn"};

} // namespace MgwPreAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
