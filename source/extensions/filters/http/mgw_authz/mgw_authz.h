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
  virtual void onComplete(bool authorized) PURE;
};

/**
 * Configuration for the Microgateway Authorization (mgw_authz) filter.
 */
class FilterConfig {
public:
  FilterConfig(const envoy::extensions::filters::http::mgw_authz::v3::MgwAuthz& ,
               const LocalInfo::LocalInfo& , Stats::Scope& ,
               Runtime::Loader& , Http::Context& ,
               const std::string& ) {}
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
  virtual void onComplete(bool authorized) override;

  Http::StreamDecoderFilterCallbacks* callbacks_{};
  FilterConfigSharedPtr config_;

private:
  enum State { Init, Calling, Continue };
  State state_ = Init;
  bool validateScopes();
};

} // namespace MgwAuthz
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
