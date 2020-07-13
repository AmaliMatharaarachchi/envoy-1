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
    if (authorized) {
      state_ = Continue;
    }
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
    std::string payloadKey = "jwt-payload";
    std::string jsonJWTPayload;
    const auto& scopes = {"scope1"};
    std::string scopeClaim = "scope";
    try {
      std::cout << callbacks_->streamInfo().dynamicMetadata().DebugString()<< std::endl;
      // std::cout << callbacks_->streamInfo().upstreamClusterInfo() << std::endl;
      const auto* jwtPayload =
          &Config::Metadata::metadataValue(&callbacks_->streamInfo().dynamicMetadata(),
                                           HttpFilterNames::get().JwtAuthn, payloadKey);
      if (jwtPayload != nullptr && jwtPayload->kind_case() != ProtobufWkt::Value::KIND_NOT_SET) {
        if (Protobuf::util::MessageToJsonString(jwtPayload->struct_value(), &jsonJWTPayload) ==
            Protobuf::util::Status::OK) {
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
            ENVOY_LOG(debug, "scope claim: " + scopeClaim + " not found in jwt payload");
          }
        } else {
          ENVOY_LOG(debug, "error while mapping payload metadata to json");
        }
      } else {
        ENVOY_LOG(debug, "payloadkey: " + payloadKey + " not exists in jwt filter metadata");
      }
    } catch (EnvoyException e) {
      ENVOY_LOG(error, "error while scope validating. ", e.what());
    } 
    return false;
  }

} // namespace ExtAuthz
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
