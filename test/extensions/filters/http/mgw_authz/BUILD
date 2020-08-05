licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_mock",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

envoy_package()

envoy_cc_library(
    name = "test_common_lib",
    hdrs = ["test_common.h"],
)

envoy_extension_cc_test(
    name = "matcher_test",
    srcs = ["matcher_test.cc"],
    extension_name = "envoy.filters.http.mgw_authz",
    deps = [
        "//source/extensions/filters/http/mgw_authz:matchers_lib",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/extensions/filters/http/mgw_authz/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test(
    name = "filter_integration_test",
    srcs = ["filter_integration_test.cc"],
    extension_name = "envoy.filters.http.mgw_authz",
    deps = [
        "//source/common/router:string_accessor_lib",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "//source/extensions/filters/http/mgw_authz:config",
        "//source/extensions/filters/http/jwt_authn:config",
        "//test/config:utility_lib",
        "//test/extensions/filters/http/common:empty_http_filter_config_lib",
        "//test/extensions/filters/http/mgw_authz:test_common_lib",
        "//test/integration:http_protocol_integration_lib",
        "@envoy_api//envoy/config/bootstrap/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/mgw_authz/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/network/http_connection_manager/v3:pkg_cc_proto",
    ],
)
