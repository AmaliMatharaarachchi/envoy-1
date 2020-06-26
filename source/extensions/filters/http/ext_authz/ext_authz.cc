#include "extensions/filters/http/ext_authz/ext_authz.h"

#include "envoy/config/core/v3/base.pb.h"

#include "common/common/assert.h"
#include "common/common/enum_to_int.h"
#include "common/http/utility.h"
#include "common/router/config_impl.h"

#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ExtAuthz {

struct RcDetailsValues {
  // The ext_authz filter denied the downstream request.
  const std::string AuthzDenied = "ext_authz_denied";
  // The ext_authz filter encountered a failure, and was configured to fail-closed.
  const std::string AuthzError = "ext_authz_error";
};
using RcDetails = ConstSingleton<RcDetailsValues>;

void FilterConfigPerRoute::merge(const FilterConfigPerRoute& other) {
  disabled_ = other.disabled_;
  auto begin_it = other.context_extensions_.begin();
  auto end_it = other.context_extensions_.end();
  for (auto it = begin_it; it != end_it; ++it) {
    context_extensions_[it->first] = it->second;
  }
}

void Filter::initiateCall(const Http::RequestHeaderMap& ,
                          const Router::RouteConstSharedPtr& route) {
  if (filter_return_ == FilterReturn::StopDecoding) {
    return;
  }

  auto&& maybe_merged_per_route_config =
      Http::Utility::getMergedPerFilterConfig<FilterConfigPerRoute>(
          HttpFilterNames::get().ExtAuthorization, route,
          [](FilterConfigPerRoute& cfg_base, const FilterConfigPerRoute& cfg) {
            cfg_base.merge(cfg);
          });

  Protobuf::Map<std::string, std::string> context_extensions;
  if (maybe_merged_per_route_config) {
    context_extensions = maybe_merged_per_route_config.value().takeContextExtensions();
  }

  // If metadata_context_namespaces is specified, pass matching metadata to the ext_authz service
  envoy::config::core::v3::Metadata metadata_context;
  const auto& request_metadata = callbacks_->streamInfo().dynamicMetadata().filter_metadata();
  for (const auto& context_key : config_->metadataContextNamespaces()) {
    const auto& metadata_it = request_metadata.find(context_key);
    if (metadata_it != request_metadata.end()) {
      (*metadata_context.mutable_filter_metadata())[metadata_it->first] = metadata_it->second;
    }
  }

  // Filters::Common::ExtAuthz::CheckRequestUtils::createSimpleHttpCheck(
  //     callbacks_, headers, std::move(context_extensions), std::move(metadata_context),
  //     check_request_, config_->maxRequestBytes(), config_->includePeerCertificate());
  

      ENVOY_STREAM_LOG(trace, "ext_authz filter calling authorization server", *callbacks_);
  state_ = State::Calling;
  filter_return_ = FilterReturn::StopDecoding; // Don't let the filter chain continue as we are
                                               // going to invoke check call.
  cluster_ = callbacks_->clusterInfo();
  initiating_call_ = true;
  client_->check(*this, check_request_, callbacks_->activeSpan(), callbacks_->streamInfo());
  initiating_call_ = false;
}

Http::FilterHeadersStatus Filter::decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) {
  Router::RouteConstSharedPtr route = callbacks_->route();
  skip_check_ = skipCheckForRoute(route);

  if (!config_->filterEnabled() || skip_check_) {
    return Http::FilterHeadersStatus::Continue;
  }

  request_headers_ = &headers;
  buffer_data_ = config_->withRequestBody() &&
                 !(end_stream || Http::Utility::isWebSocketUpgradeRequest(headers) ||
                   Http::Utility::isH2UpgradeRequest(headers));
  if (buffer_data_) {
    ENVOY_STREAM_LOG(debug, "ext_authz filter is buffering the request", *callbacks_);
    if (!config_->allowPartialMessage()) {
      callbacks_->setDecoderBufferLimit(config_->maxRequestBytes());
    }
    return Http::FilterHeadersStatus::StopIteration;
  }

  // Initiate a call to the authorization server since we are not disabled.
  initiateCall(headers, route);
  return filter_return_ == FilterReturn::StopDecoding
             ? Http::FilterHeadersStatus::StopAllIterationAndWatermark
             : Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus Filter::decodeData(Buffer::Instance& data, bool end_stream) {
  if (buffer_data_ && !skip_check_) {
    const bool buffer_is_full = isBufferFull();
    if (end_stream || buffer_is_full) {
      ENVOY_STREAM_LOG(debug, "ext_authz filter finished buffering the request since {}",
                       *callbacks_, buffer_is_full ? "buffer is full" : "stream is ended");
      if (!buffer_is_full) {
        // Make sure data is available in initiateCall.
        callbacks_->addDecodedData(data, true);
      }
      initiateCall(*request_headers_, callbacks_->route());
      return filter_return_ == FilterReturn::StopDecoding
                 ? Http::FilterDataStatus::StopIterationAndWatermark
                 : Http::FilterDataStatus::Continue;
    } else {
      return Http::FilterDataStatus::StopIterationAndBuffer;
    }
  }

  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus Filter::decodeTrailers(Http::RequestTrailerMap&) {
  if (buffer_data_ && !skip_check_) {
    if (filter_return_ != FilterReturn::StopDecoding) {
      ENVOY_STREAM_LOG(debug, "ext_authz filter finished buffering the request", *callbacks_);
      initiateCall(*request_headers_, callbacks_->route());
    }
    return filter_return_ == FilterReturn::StopDecoding ? Http::FilterTrailersStatus::StopIteration
                                                        : Http::FilterTrailersStatus::Continue;
  }

  return Http::FilterTrailersStatus::Continue;
}

void Filter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;
}

void Filter::onDestroy() {
  if (state_ == State::Calling) {
    state_ = State::Complete;
    client_->cancel();
  }
}

void Filter::onComplete(Filters::Common::ExtAuthz::ResponsePtr&& ) {
  continueDecoding();
}

bool Filter::isBufferFull() const {
  const auto* buffer = callbacks_->decodingBuffer();
  if (config_->allowPartialMessage() && buffer != nullptr) {
    return buffer->length() >= config_->maxRequestBytes();
  }
  return false;
}

void Filter::continueDecoding() {
  filter_return_ = FilterReturn::ContinueDecoding;
  if (!initiating_call_) {
    callbacks_->continueDecoding();
  }
}

bool Filter::skipCheckForRoute(const Router::RouteConstSharedPtr& route) const {
  if (route == nullptr || route->routeEntry() == nullptr) {
    return true;
  }

  const auto* specific_per_route_config =
      Http::Utility::resolveMostSpecificPerFilterConfig<FilterConfigPerRoute>(
          HttpFilterNames::get().ExtAuthorization, route);
  if (specific_per_route_config != nullptr) {
    return specific_per_route_config->disabled();
  }

  return false;
}

} // namespace ExtAuthz
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
