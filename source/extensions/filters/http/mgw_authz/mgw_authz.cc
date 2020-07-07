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
  bool doValidateScopes = true;
  if (doValidateScopes) {
    validateScopes();
  }

  return Http::FilterHeadersStatus::Continue;
}

Http::FilterDataStatus Filter::decodeData(Buffer::Instance& , bool ) {
  std::cout << "mgw decode data" << std::endl;
  return Http::FilterDataStatus::Continue;
}

Http::FilterTrailersStatus Filter::decodeTrailers(Http::RequestTrailerMap&) {
  std::cout << "mgw decode trailer" << std::endl;
  return Http::FilterTrailersStatus::Continue;
}

void Filter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;
}

void Filter::onDestroy() {
}

bool Filter::validateScopes() {
  std::cout << "validate scopes" << std::endl;
  std::string payloadKey = "my-payload";
  std::string jsonJWTPayload;
  absl::string_view scope = "scope1";
  std::string scopeClaim = "scope";

  const Protobuf::Map<std::string, Protobuf::Struct> filter_metadata = callbacks_->streamInfo().dynamicMetadata().filter_metadata();
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
          if (std::find(scopesList.begin(), scopesList.end(), scope) != scopesList.end()) {
            std::cout << "scope exists" << std::endl;
            return true;
          } else {
            std::cout << "scope does not exists in jwt payload" << std::endl;
          }
        } else {
          std::cout << "scope claim not exists in jwt payload" << std::endl;
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
