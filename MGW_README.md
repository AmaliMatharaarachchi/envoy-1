# Build the envoy binary
- `bazel build //source/exe:envoy-static`

# Run the envoy gateway
- Go to bazel-bin symlinked location
- `cd source/exe`
- `./envoy-static -c <config file> -l <log level>`

# Add the mgw filter

Sample config would something similar the to the following. Refer "<envoy repo>/api/envoy/config/filter/http/mgw/v2/mgw.proto" for more details.
```
http_filters:
- name: envoy.mgw
    typed_config:
        "@type": type.googleapis.com/envoy.config.filter.http.mgw.v2.MGW
        request:
            grpc_service:
                envoy_grpc:
                cluster_name: ext-authz 
                timeout: 600s
        response:
            grpc_service:
                envoy_grpc:
                cluster_name: mgw-res
```
