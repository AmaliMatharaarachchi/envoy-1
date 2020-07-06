licenses(["notice"])  # Apache 2

# External authorization L7 HTTP filter
# Public docs: TODO(saumoh): Docs needed in docs/root/configuration/http_filters

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "mgw_authz",
    srcs = ["mgw_authz.cc"],
    hdrs = ["mgw_authz.h"],
    deps = [
        "//include/envoy/http:codes_interface",
        "//include/envoy/stats:stats_macros",
        "//include/envoy/http:context_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:assert_lib",
        "//source/common/common:empty_string",
        "//source/common/common:enum_to_int",
        "//source/common/common:matchers_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/http:codes_lib",
        "//source/common/http:utility_lib",
        "//source/common/router:config_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/mgw_authz/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/auth/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    security_posture = "robust_to_untrusted_downstream",
    deps = [
        ":mgw_authz",
        "//include/envoy/registry",
        "//include/envoy/stats:stats_macros",
        "//source/common/protobuf:utility_lib",
        "//source/extensions/filters/http:well_known_names",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/mgw_authz/v3:pkg_cc_proto",
    ],
)
