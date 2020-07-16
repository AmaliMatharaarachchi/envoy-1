#pragma once

#include "envoy/extensions/filters/http/mgw_pre_authn/v3/mgw_pre_authn.pb.h"
#include "envoy/extensions/filters/http/mgw_pre_authn/v3/mgw_pre_authn.pb.validate.h"

#include "extensions/filters/http/common/factory_base.h"
#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace MgwPreAuthn {

/**
 * Config registration for the external authorization filter. @see NamedHttpFilterConfigFactory.
 */
class MgwPreAuthnFilterConfig
    : public Common::FactoryBase<
          envoy::extensions::filters::http::mgw_pre_authn::v3::MgwPreAuthn> {
public:
  MgwPreAuthnFilterConfig() : FactoryBase(HttpFilterNames::get().MgwPreAuthn) {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::mgw_pre_authn::v3::MgwPreAuthn& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
};

} // namespace MgwPreAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
