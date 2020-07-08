#include "extensions/filters/http/mgw_authz/mgw_authz.h"

#include "envoy/config/core/v3/base.pb.h"

#include "common/common/assert.h"
#include "common/common/enum_to_int.h"
#include "common/http/utility.h"
#include "common/router/config_impl.h"

#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MgwAuthz {

Http::FilterHeadersStatus Filter::decodeHeaders(Http::RequestHeaderMap& , bool ) {
  state_ = Calling;
  bool doValidateScopes = true;
  if (doValidateScopes) {
    bool authorized = validateScopes();
    onComplete(authorized);
  } else {
    state_ = Continue;
  }
  if (state_ == Continue) {
    return Http::FilterHeadersStatus::Continue;
  }
  ENVOY_LOG(debug, "Called Filter : {} Stop", __func__);
  return Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus Filter::decodeData(Buffer::Instance& , bool ) {
  std::cout << "mgw decode data" << std::endl;
  if (state_ == Calling) {
    return Http::FilterDataStatus::StopIterationAndWatermark;
  }
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus Filter::decodeTrailers(Http::RequestTrailerMap&) {
  std::cout << "mgw decode trailer" << std::endl;
  if (state_ == Calling) {
    return Http::FilterTrailersStatus::StopIteration;
  }
  return Http::FilterTrailersStatus::Continue;
}

void Filter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;
}

void Filter::onDestroy() {
}
void Filter::onComplete(bool authorized) {
  if (!authorized) {
    // todo move to common const
    std::string errorDescription = "Access failure for API";
    std::string errorMessage = "The access token does not allow you to access the requested "
                               "resource";
    std::string errorCode = "900910";
    // send unauthorized local response. this sent in plain text
    // status: forbidden
    callbacks_->sendLocalReply(Http::Code::Forbidden,
                               "fault: { code: " + errorCode + ", message: " + errorMessage +
                                   ", description: " + errorDescription,
                               nullptr, absl::nullopt, errorDescription);
  }
}

  bool Filter::validateScopes() {
    ENVOY_LOG(debug, "validate scopes");
    std::cout << "validate scopes" << std::endl;
    std::string payloadKey = "my-payload";
    std::string jsonJWTPayload;
    const auto& scopes = {"scope2"};
    std::string scopeClaim = "scope";

    const Protobuf::Map<std::string, Protobuf::Struct> filter_metadata =
        callbacks_->streamInfo().dynamicMetadata().filter_metadata();
    const auto filter_it = filter_metadata.find(HttpFilterNames::get().JwtAuthn);
    if (filter_it != filter_metadata.end()) { // if jwtauthn filter
                                              // meta data exists.
      const auto jwt_filter_it =
          filter_metadata.at(HttpFilterNames::get().JwtAuthn).fields().find(payloadKey);
      if (jwt_filter_it != filter_metadata.at(HttpFilterNames::get().JwtAuthn).fields().end()) {
        const auto status =
            Protobuf::util::MessageToJsonString(filter_metadata.at(HttpFilterNames::get().JwtAuthn)
                                                    .fields()
                                                    .at(payloadKey)
                                                    .struct_value(),
                                                &jsonJWTPayload);
        if (status == Protobuf::util::Status::OK) {
          Json::ObjectSharedPtr loader = Json::Factory::loadFromString(jsonJWTPayload);
          if (loader->hasObject(scopeClaim)) {
            std::string scopesFromPayload = loader->getString(scopeClaim);
            std::vector<absl::string_view> scopesList =
                StringUtil::splitToken(scopesFromPayload, " ");
            for (absl::string_view scope : scopes) {
              if (std::find(scopesList.begin(), scopesList.end(), scope) != scopesList.end()) {
                ENVOY_LOG(debug, "scopes validated successfully");
                return true;
              }
            }
            ENVOY_LOG(debug, "scope does not exists in jwt payload");

          } else {
            ENVOY_LOG(debug, "scope claim not exists in jwt payload");
          }
        }
      }
    }
    return false;
  }

} // namespace ExtAuthz
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
