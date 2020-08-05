#pragma once

#include "envoy/extensions/filters/http/mgw_authz/v3/mgw_authz.pb.h"
#include "envoy/extensions/filters/http/mgw_authz/v3/mgw_authz.pb.validate.h"

#include "extensions/filters/http/common/factory_base.h"
#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MgwAuthz {

/**
 * Config registration for the external authorization filter. @see NamedHttpFilterConfigFactory.
 */
class MgwAuthzFilterConfig
    : public Common::FactoryBase<
          envoy::extensions::filters::http::mgw_authz::v3::MgwAuthz> {
public:
  MgwAuthzFilterConfig() : FactoryBase(HttpFilterNames::get().MgwAuthorization) {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::mgw_authz::v3::MgwAuthz& proto_config,
      const std::string& , Server::Configuration::FactoryContext& ) override;
};

} // namespace MgwAuthz
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
