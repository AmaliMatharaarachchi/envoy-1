#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/extensions/filters/http/mgw_authz/v3/mgw_authz.pb.h"
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
#include "extensions/filters/http/mgw_authz/matcher.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MgwAuthz {

class RequestCallbacks {
public:
  virtual ~RequestCallbacks() = default;

  /**
   * Called when authorization is complete. The resulting ResponsePtr is supplied.
   */
  virtual void onComplete() PURE;
};

/**
 * Configuration for the Microgateway Authorization (mgw_authz) filter.
 */
class FilterConfig {
public:
  FilterConfig(const envoy::extensions::filters::http::mgw_authz::v3::MgwAuthz& proto_config)
      : proto_config_(std::move(proto_config)) {
    for (const auto& rule : proto_config_.rules()) {
      rule_pairs_.emplace_back(Matcher::create(rule),
                               rule.scopes());                        
    }
    jwt_config_ = proto_config_.jwt_config();
  }

  std::string findScopes(const Http::RequestHeaderMap& headers) {
    for (const auto& pair : rule_pairs_) {
      if (pair.matcher_->matches(headers)) {
          return pair.scope_;
      }
    }
    return "";
  }

  std::string getScopeClaim(std::string issuer) {
    for (auto& pair : jwt_config_) {
      if (pair.second.issuer() == issuer) {
        return pair.second.claim();
      }
    }
    return "scope";
  }

private:
  struct MatcherScopePair {
    MatcherScopePair(MatcherConstPtr matcher, std::string scope)
        : matcher_(std::move(matcher)), scope_(scope) {}
    MatcherConstPtr matcher_;
    std::string scope_;
    };
  // The list of rules and scopes.
    std::vector<MatcherScopePair> rule_pairs_;
    envoy::extensions::filters::http::mgw_authz::v3::MgwAuthz proto_config_;
    Protobuf::Map<std::string, envoy::extensions::filters::http::mgw_authz::v3::ScopesClaimsMap> jwt_config_;
};

using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

/**
 * HTTP ext_authz filter. Depending on the route configuration, this filter calls the global
 * ext_authz service before allowing further filter iteration.
 */
class Filter : public Logger::Loggable<Logger::Id::filter>,
               public Http::StreamDecoderFilter,
               public RequestCallbacks {
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
  // RequestCallbacks
  virtual void onComplete() override;
  void sendError();

  Http::StreamDecoderFilterCallbacks* callbacks_{};
  FilterConfigSharedPtr config_;

private:
  enum State { Init, Calling, Continue };
  State state_ = Init;
  bool validateScopes(std::string scopes);
};

} // namespace MgwAuthz
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
