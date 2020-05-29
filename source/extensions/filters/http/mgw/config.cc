#include "extensions/filters/http/mgw/config.h"

#include <chrono>
#include <string>

#include "envoy/config/core/v3/grpc_service.pb.h"
#include "envoy/extensions/filters/http/mgw/v3/mgw.pb.h"
#include "envoy/extensions/filters/http/mgw/v3/mgw.pb.validate.h"
#include "envoy/registry/registry.h"

#include "common/protobuf/utility.h"

#include "extensions/filters/common/mgw/mgw_grpc_impl.h"
#include "extensions/filters/common/mgw/mgw_http_impl.h"
#include "extensions/filters/http/mgw/mgw.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MGW {

Http::FilterFactoryCb MGWFilterConfig::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::mgw::v3::MGW& proto_config,
    const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {
  const auto filter_config =
      std::make_shared<FilterConfig>(proto_config, context.localInfo(), context.scope(),
                                     context.runtime(), context.httpContext(), stats_prefix);
  Http::FilterFactoryCb callback;

  if (proto_config.has_http_service()) {
    // Raw HTTP client.
    const uint32_t timeout_ms = PROTOBUF_GET_MS_OR_DEFAULT(proto_config.http_service().server_uri(),
                                                           timeout, DefaultTimeout);
    const auto client_config =
        std::make_shared<Extensions::Filters::Common::MGW::ClientConfig>(
            proto_config, timeout_ms, proto_config.http_service().path_prefix());
    callback = [filter_config, client_config,
                &context](Http::FilterChainFactoryCallbacks& callbacks) {
      auto client = std::make_unique<Extensions::Filters::Common::MGW::RawHttpClientImpl>(
          context.clusterManager(), client_config, context.timeSource());
      callbacks.addStreamDecoderFilter(Http::StreamDecoderFilterSharedPtr{
          std::make_shared<Filter>(filter_config, std::move(client))});
    };
  } else {
    // gRPC client.
    const uint32_t timeout_ms =
        PROTOBUF_GET_MS_OR_DEFAULT(proto_config.grpc_service(), timeout, DefaultTimeout);
    callback = [grpc_service = proto_config.grpc_service(), &context, filter_config, timeout_ms,
                use_alpha = proto_config.hidden_envoy_deprecated_use_alpha()](
                   Http::FilterChainFactoryCallbacks& callbacks) {
      const auto async_client_factory =
          context.clusterManager().grpcAsyncClientManager().factoryForGrpcService(
              grpc_service, context.scope(), true);
      auto client = std::make_unique<Filters::Common::MGW::GrpcClientImpl>(
          async_client_factory->create(), std::chrono::milliseconds(timeout_ms), use_alpha);
      callbacks.addStreamDecoderFilter(Http::StreamDecoderFilterSharedPtr{
          std::make_shared<Filter>(filter_config, std::move(client))});
    };
  }

  return callback;
};

Router::RouteSpecificFilterConfigConstSharedPtr
MGWFilterConfig::createRouteSpecificFilterConfigTyped(
    const envoy::extensions::filters::http::mgw::v3::MGWPerRoute& proto_config,
    Server::Configuration::ServerFactoryContext&, ProtobufMessage::ValidationVisitor&) {
  return std::make_shared<FilterConfigPerRoute>(proto_config);
}

/**
 * Static registration for the external authorization filter. @see RegisterFactory.
 */
REGISTER_FACTORY(MGWFilterConfig,
                 Server::Configuration::NamedHttpFilterConfigFactory){"envoy.mgw"};

} // namespace MGW
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
