#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/extensions/filters/http/mgw_pre_authn/v3/mgw_pre_authn.pb.h"
#include "envoy/http/filter.h"
#include "envoy/http/context.h"
#include "envoy/local_info/local_info.h"
#include "envoy/runtime/runtime.h"
#include "envoy/stats/scope.h"
#include "envoy/upstream/cluster_manager.h"

#include "common/common/assert.h"
#include "common/common/logger.h"
#include "common/common/matchers.h"
#include "common/http/codes.h"
#include "common/http/header_map_impl.h"
#include "common/runtime/runtime_protos.h"
#include "extensions/filters/http/mgw_pre_authn/matcher.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MgwPreAuthn {

/**
 * Configuration for the Microgateway (mgw_pre_authn) filter.
 */
class FilterConfig {
public:
  FilterConfig(
      const envoy::extensions::filters::http::mgw_pre_authn::v3::MgwPreAuthn& proto_config_,
      const LocalInfo::LocalInfo&, Stats::Scope&, Runtime::Loader&, Http::Context&,
      const std::string&)
      : jwt_issuers_(std::move(proto_config_.jwt_issuers())), api_config_(std::move(proto_config_.api_config())) {
    for (const auto& rule : proto_config_.rules()) {
      rule_pairs_.emplace_back(Matcher::create(rule),
                               rule.resource_config());
    }
  }

private:
  struct MatcherConfigPair {
    MatcherConfigPair(
        MatcherConstPtr matcher,
        envoy::extensions::filters::http::mgw_pre_authn::v3::ResourceConfig resource_config)
        : matcher_(std::move(matcher)), resource_config_(resource_config) {}
    MatcherConstPtr matcher_;
    envoy::extensions::filters::http::mgw_pre_authn::v3::ResourceConfig resource_config_;
  };
  // The list of rules and scopes.
  std::vector<MatcherConfigPair> rule_pairs_;
  Protobuf::Map<std::string, envoy::extensions::filters::http::mgw_pre_authn::v3::JwtIssuer>
      jwt_issuers_;
  envoy::extensions::filters::http::mgw_pre_authn::v3::ApiConfig api_config_;
  
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

/**
 * HTTP filter. Depending on the route configuration, this filter calls the global
 * service before allowing further filter iteration.
 */
class Filter : public Logger::Loggable<Logger::Id::filter>,
               public Http::StreamDecoderFilter {
public:
  Filter(const FilterConfigSharedPtr& config) : config_(config) {}

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap& trailers) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

  Http::StreamDecoderFilterCallbacks* callbacks_{};
  FilterConfigSharedPtr config_;

private:
};

} // namespace MgwPreAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
