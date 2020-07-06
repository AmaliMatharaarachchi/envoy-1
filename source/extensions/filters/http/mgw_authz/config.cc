#include "extensions/filters/http/mgw_authz/config.h"

#include <chrono>
#include <string>

// #include "envoy/config/core/v3/grpc_service.pb.h"
#include "envoy/extensions/filters/http/mgw_authz/v3/mgw_authz.pb.h"
#include "envoy/extensions/filters/http/mgw_authz/v3/mgw_authz.pb.validate.h"
#include "envoy/registry/registry.h"

#include "common/protobuf/utility.h"

#include "extensions/filters/http/mgw_authz/mgw_authz.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MgwAuthz {

Http::FilterFactoryCb MgwAuthzFilterConfig::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::mgw_authz::v3::MgwAuthz& proto_config,
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

  return callback;
};

/**
 * Static registration for the mgw authorization filter. @see RegisterFactory.
 */
REGISTER_FACTORY(MgwAuthzFilterConfig,
                 Server::Configuration::NamedHttpFilterConfigFactory){"envoy.mgw_authz"};

} // namespace MgwAuthz
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
