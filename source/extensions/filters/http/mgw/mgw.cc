#include "extensions/filters/http/mgw/mgw.h"

#include "envoy/config/core/v3/base.pb.h"

#include "common/common/assert.h"
#include "common/common/enum_to_int.h"
#include "common/http/utility.h"
#include "common/router/config_impl.h"

#include "extensions/filters/http/well_known_names.h"
#include "extensions/filters/common/mgw/check_response_utils.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MGW {

struct RcDetailsValues {
  // The mgw filter denied the downstream request.
  const std::string AuthzDenied = "mgw_denied";
  // The mgw filter encountered a failure, and was configured to fail-closed.
  const std::string AuthzError = "mgw_error";
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

void Filter::initiateCall(const Http::RequestHeaderMap& headers,
                          const Router::RouteConstSharedPtr& route) {
  if (filter_return_ == FilterReturn::StopDecoding) {
    return;
  }

  auto&& maybe_merged_per_route_config =
      Http::Utility::getMergedPerFilterConfig<FilterConfigPerRoute>(
          HttpFilterNames::get().MGW, route,
          [](FilterConfigPerRoute& cfg_base, const FilterConfigPerRoute& cfg) {
            cfg_base.merge(cfg);
          });

  Protobuf::Map<std::string, std::string> context_extensions;
  if (maybe_merged_per_route_config) {
    context_extensions = maybe_merged_per_route_config.value().takeContextExtensions();
  }

  // If metadata_context_namespaces is specified, pass matching metadata to the mgw service
  envoy::config::core::v3::Metadata metadata_context;
  const auto& request_metadata = callbacks_->streamInfo().dynamicMetadata().filter_metadata();
  for (const auto& context_key : config_->metadataContextNamespaces()) {
    const auto& metadata_it = request_metadata.find(context_key);
    if (metadata_it != request_metadata.end()) {
      (*metadata_context.mutable_filter_metadata())[metadata_it->first] = metadata_it->second;
    }
  }

  Filters::Common::MGW::CheckRequestUtils::createHttpCheck(
      callbacks_, headers, std::move(context_extensions), std::move(metadata_context),
      check_request_, config_->maxRequestBytes(), config_->includePeerCertificate());

  ENVOY_STREAM_LOG(trace, "mgw filter calling authorization server", *callbacks_);
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
    ENVOY_STREAM_LOG(debug, "mgw filter is buffering the request", *callbacks_);
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
      ENVOY_STREAM_LOG(debug, "mgw filter finished buffering the request since {}",
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
      ENVOY_STREAM_LOG(debug, "mgw filter finished buffering the request", *callbacks_);
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
    res_state_ = State::Complete;
    client_->cancel();
    res_client_->cancel();
  }
}

void Filter::onComplete(Filters::Common::MGW::ResponsePtr&& response) {
  state_ = State::Complete;
  using Filters::Common::MGW::CheckStatus;
  Stats::StatName empty_stat_name;

  switch (response->status) {
  case CheckStatus::OK: {
    ENVOY_STREAM_LOG(trace, "mgw filter added header(s) to the request:", *callbacks_);
    if (config_->clearRouteCache() &&
        (!response->headers_to_add.empty() || !response->headers_to_append.empty())) {
      ENVOY_STREAM_LOG(debug, "mgw is clearing route cache", *callbacks_);
      callbacks_->clearRouteCache();
    }
    for (const auto& header : response->headers_to_add) {
      ENVOY_STREAM_LOG(trace, "'{}':'{}'", *callbacks_, header.first.get(), header.second);
      request_headers_->setCopy(header.first, header.second);
    }
    for (const auto& header : response->headers_to_append) {
      const Http::HeaderEntry* header_to_modify = request_headers_->get(header.first);
      if (header_to_modify) {
        ENVOY_STREAM_LOG(trace, "'{}':'{}'", *callbacks_, header.first.get(), header.second);
        request_headers_->appendCopy(header.first, header.second);
      }
    }
    if (cluster_) {
      config_->incCounter(cluster_->statsScope(), config_->mgw_ok_);
    }
    stats_.ok_.inc();
    continueDecoding();
    break;
  }

  case CheckStatus::Denied: {
    ENVOY_STREAM_LOG(trace, "mgw filter rejected the request. Response status code: '{}",
                     *callbacks_, enumToInt(response->status_code));
    stats_.denied_.inc();

    if (cluster_) {
      config_->incCounter(cluster_->statsScope(), config_->mgw_denied_);

      Http::CodeStats::ResponseStatInfo info{config_->scope(),
                                             cluster_->statsScope(),
                                             empty_stat_name,
                                             enumToInt(response->status_code),
                                             true,
                                             empty_stat_name,
                                             empty_stat_name,
                                             empty_stat_name,
                                             empty_stat_name,
                                             false};
      config_->httpContext().codeStats().chargeResponseStat(info);
    }

    callbacks_->sendLocalReply(
        response->status_code, response->body,
        [& headers = response->headers_to_add,
         &callbacks = *callbacks_](Http::HeaderMap& response_headers) -> void {
          ENVOY_STREAM_LOG(trace,
                           "mgw filter added header(s) to the local response:", callbacks);
          // First remove all headers requested by the mgw filter,
          // to ensure that they will override existing headers
          for (const auto& header : headers) {
            response_headers.remove(header.first);
          }
          // Then set all of the requested headers, allowing the
          // same header to be set multiple times, e.g. `Set-Cookie`
          for (const auto& header : headers) {
            ENVOY_STREAM_LOG(trace, " '{}':'{}'", callbacks, header.first.get(), header.second);
            response_headers.addCopy(header.first, header.second);
          }
        },
        absl::nullopt, RcDetails::get().AuthzDenied);
    callbacks_->streamInfo().setResponseFlag(StreamInfo::ResponseFlag::UnauthorizedExternalService);
    break;
  }

  case CheckStatus::Error: {
    if (cluster_) {
      config_->incCounter(cluster_->statsScope(), config_->mgw_error_);
    }
    stats_.error_.inc();
    if (config_->failureModeAllow()) {
      ENVOY_STREAM_LOG(trace, "mgw filter allowed the request with error", *callbacks_);
      stats_.failure_mode_allowed_.inc();
      if (cluster_) {
        config_->incCounter(cluster_->statsScope(), config_->mgw_failure_mode_allowed_);
      }
      continueDecoding();
    } else {
      ENVOY_STREAM_LOG(
          trace, "mgw filter rejected the request with an error. Response status code: {}",
          *callbacks_, enumToInt(config_->statusOnError()));
      callbacks_->streamInfo().setResponseFlag(
          StreamInfo::ResponseFlag::UnauthorizedExternalService);
      callbacks_->sendLocalReply(config_->statusOnError(), EMPTY_STRING, nullptr, absl::nullopt,
                                 RcDetails::get().AuthzError);
    }
    break;
  }

  default:
    NOT_REACHED_GCOVR_EXCL_LINE;
    break;
  }
}

void Filter::onResponseComplete(Filters::Common::MGW::ResponsePtr&& response) {
  res_state_ = State::Complete;
  using Filters::Common::MGW::CheckStatus;
  Stats::StatName empty_stat_name;
  std::cout << "response" << response << std::endl;
  switch (response->status) {
  case CheckStatus::OK: {
    ENVOY_STREAM_LOG(trace, "mgw filter added header(s) to the response:", *res_callbacks_);
    if (config_->clearRouteCache() &&
        (!response->headers_to_add.empty() || !response->headers_to_append.empty())) {
      ENVOY_STREAM_LOG(debug, "mgw is clearing route cache", *res_callbacks_);
      res_callbacks_->clearRouteCache();
    }
    for (const auto& header : response->headers_to_add) {
      ENVOY_STREAM_LOG(trace, "'{}':'{}'", *res_callbacks_, header.first.get(), header.second);
      response_headers_->setCopy(header.first, header.second);
    }
    for (const auto& header : response->headers_to_append) {
      const Http::HeaderEntry* header_to_modify = response_headers_->get(header.first);
      if (header_to_modify) {
        ENVOY_STREAM_LOG(trace, "'{}':'{}'", *res_callbacks_, header.first.get(), header.second);
        response_headers_->appendCopy(header.first, header.second);
      }
    }
    if (cluster_) {
      config_->incCounter(cluster_->statsScope(), config_->mgw_ok_);
    }
    stats_.ok_.inc();
    continueEncoding();
    break;
  }

  case CheckStatus::Denied: {
    ENVOY_STREAM_LOG(trace, "mgw filter rejected the request. Response status code: '{}",
                     *res_callbacks_, enumToInt(response->status_code));
    stats_.denied_.inc();

    if (cluster_) {
      config_->incCounter(cluster_->statsScope(), config_->mgw_denied_);

      Http::CodeStats::ResponseStatInfo info{config_->scope(),
                                             cluster_->statsScope(),
                                             empty_stat_name,
                                             enumToInt(response->status_code),
                                             true,
                                             empty_stat_name,
                                             empty_stat_name,
                                             empty_stat_name,
                                             empty_stat_name,
                                             false};
      config_->httpContext().codeStats().chargeResponseStat(info);
    }
    // ENVOY_STREAM_LOG(trace, "mgw filter added header(s) to the local response:", res_callbacks);
    // // First remove all headers requested by the mgw filter,
    // // to ensure that they will override existing headers
    // for (const auto& header : headers) {
    //   response_headers.remove(header.first);
    // }
    // // Then set all of the requested headers, allowing the
    // // same header to be set multiple times, e.g. `Set-Cookie`
    // for (const auto& header : headers) {
    //   ENVOY_STREAM_LOG(trace, " '{}':'{}'", res_callbacks, header.first.get(), header.second);
    //   response_headers.addCopy(header.first, header.second);
    // }

    // res_callbacks_->sendLocalReply(
    //     response->status_code, response->body,
    //     [& headers = response->headers_to_add,
    //      &callbacks = *res_callbacks_](Http::HeaderMap& response_headers) -> void {
    //       ENVOY_STREAM_LOG(trace,
    //                        "mgw filter added header(s) to the local response:", callbacks);
    //       // First remove all headers requested by the mgw filter,
    //       // to ensure that they will override existing headers
    //       for (const auto& header : headers) {
    //         response_headers.remove(header.first);
    //       }
    //       // Then set all of the requested headers, allowing the
    //       // same header to be set multiple times, e.g. `Set-Cookie`
    //       for (const auto& header : headers) {
    //         ENVOY_STREAM_LOG(trace, " '{}':'{}'", callbacks, header.first.get(), header.second);
    //         response_headers.addCopy(header.first, header.second);
    //       }
    //     },
        // absl::nullopt, RcDetails::get().AuthzDenied);
    // res_callbacks_->streamInfo().setResponseFlag(StreamInfo::ResponseFlag::UnauthorizedExternalService);
    response_filter_return_ = ResponseFilterReturn::StopEncoding;
    break;
  }

  case CheckStatus::Error: {
    if (downstream_cluster_) {
      config_->incCounter(downstream_cluster_->statsScope(), config_->mgw_error_);
    }
    stats_.error_.inc();
    if (config_->failureModeAllow()) {
      ENVOY_STREAM_LOG(trace, "mgw filter allowed the request with error", *res_callbacks_);
      stats_.failure_mode_allowed_.inc();
      if (downstream_cluster_) {
        config_->incCounter(downstream_cluster_->statsScope(), config_->mgw_failure_mode_allowed_);
      }
      continueEncoding();
    } else {
      ENVOY_STREAM_LOG(
          trace, "mgw filter rejected the request with an error. Response status code: {}",
          *res_callbacks_, enumToInt(config_->statusOnError()));
      //TODO(amalimatharaarachchi) Gracefully handle error response
      // res_callbacks_->streamInfo().setResponseFlag(
      //     StreamInfo::ResponseFlag::UnauthorizedExternalService);
      // res_callbacks_->sendLocalReply(config_->statusOnError(), EMPTY_STRING, nullptr, absl::nullopt,
      //                            RcDetails::get().AuthzError);
      response_filter_return_ = ResponseFilterReturn::StopEncoding;
    }
    break;
  }

  default:
    NOT_REACHED_GCOVR_EXCL_LINE;
    break;
  }
}

// set encode abstract methods overriden
Http::FilterHeadersStatus Filter::encodeHeaders(Http::ResponseHeaderMap& headers, bool) {
  Router::RouteConstSharedPtr route = res_callbacks_->route();
  skip_check_ = skipCheckForRoute(route);

  if (!config_->filterEnabled() || skip_check_) {
    return Http::FilterHeadersStatus::Continue;
  }

  response_headers_ = &headers;

  // TODO(amalimatharaarachchi) check this
  // buffer_data_ = config_->withRequestBody() &&
  //                !(end_stream || Http::Utility::isWebSocketUpgradeRequest(headers) ||
  //                  Http::Utility::isH2UpgradeRequest(headers));
  // if (buffer_data_) {
  //   ENVOY_STREAM_LOG(debug, "mgw filter is buffering the request", *res_callbacks_);
  //   if (!config_->allowPartialMessage()) {
  //     res_callbacks_->setDecoderBufferLimit(config_->maxRequestBytes());
  //   }
  //   return Http::FilterHeadersStatus::StopIteration;
  // }

  // Initiate a call to the authorization server since we are not disabled.
  initiateResponseInterceptCall(headers, route);
  return response_filter_return_ == ResponseFilterReturn::StopEncoding
             ? Http::FilterHeadersStatus::StopAllIterationAndWatermark
             : Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus Filter::encode100ContinueHeaders(Http::ResponseHeaderMap&) {
  return response_filter_return_ == ResponseFilterReturn::StopEncoding
             ? Http::FilterHeadersStatus::StopAllIterationAndWatermark
             : Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus Filter::encodeData(Buffer::Instance&, bool) {
  ENVOY_LOG(info, "[woohoo] inside encode data");
  return response_filter_return_ == ResponseFilterReturn::StopEncoding
              ? Http::FilterDataStatus::StopIterationAndWatermark
              : Http::FilterDataStatus::Continue;
}
Http::FilterTrailersStatus Filter::encodeTrailers(Http::ResponseTrailerMap&) {
  return response_filter_return_ == ResponseFilterReturn::StopEncoding
             ? Http::FilterTrailersStatus::StopIteration
             : Http::FilterTrailersStatus::Continue;
}
Http::FilterMetadataStatus Filter::encodeMetadata(Http::MetadataMap&) {
  return Http::FilterMetadataStatus::Continue;
}
void Filter::setEncoderFilterCallbacks(
    Http::StreamEncoderFilterCallbacks& callbacks) {
    res_callbacks_ = &callbacks;
}
////////////////////

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
          HttpFilterNames::get().MGW, route);
  if (specific_per_route_config != nullptr) {
    return specific_per_route_config->disabled();
  }

  return false;
}

////////// Encode methods /////////////////

void Filter::continueEncoding() {
  response_filter_return_ = ResponseFilterReturn::ContinueEncoding;
  if (!initiating_responce_call_) {
    res_callbacks_->continueEncoding();
  }
}

void Filter::initiateResponseInterceptCall(const Http::ResponseHeaderMap& headers,
                                           const Router::RouteConstSharedPtr& route) {
  if (response_filter_return_ == ResponseFilterReturn::StopEncoding) {
    return;
  }

  auto&& maybe_merged_per_route_config =
      Http::Utility::getMergedPerFilterConfig<FilterConfigPerRoute>(
          HttpFilterNames::get().MGW, route,
          [](FilterConfigPerRoute& cfg_base, const FilterConfigPerRoute& cfg) {
            cfg_base.merge(cfg);
          });

  Protobuf::Map<std::string, std::string> context_extensions;
  if (maybe_merged_per_route_config) {
    context_extensions = maybe_merged_per_route_config.value().takeContextExtensions();
  }

  // If metadata_context_namespaces is specified, pass matching metadata to the mgw service
  envoy::config::core::v3::Metadata metadata_context;
  const auto& response_metadata = res_callbacks_->streamInfo().dynamicMetadata().filter_metadata();
  for (const auto& context_key : config_->metadataContextNamespaces()) {
    const auto& metadata_it = response_metadata.find(context_key);
    if (metadata_it != response_metadata.end()) {
      (*metadata_context.mutable_filter_metadata())[metadata_it->first] = metadata_it->second;
    }
  }

  Filters::Common::MGW::CheckResponseUtils::createHttpCheck(
      res_callbacks_, headers, std::move(context_extensions), std::move(metadata_context),
      check_res_request_, config_->maxRequestBytes(), config_->includePeerCertificate());

  ENVOY_STREAM_LOG(trace, "mgw filter calling response interceptor server", *res_callbacks_);
  res_state_ = State::Calling;
  response_filter_return_ = ResponseFilterReturn::StopEncoding;
  cluster_ = res_callbacks_->clusterInfo();
  initiating_responce_call_ = true;
  res_client_->intercept(*this, check_res_request_, res_callbacks_->activeSpan(),
                         res_callbacks_->streamInfo());
  initiating_responce_call_ = false;
}

} // namespace MGW
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy