#include "extensions/filters/common/ext_authz/ext_authz_simple_grpc_impl.h"

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/service/auth_simple/v3/auth_simple.pb.h"

#include "common/common/assert.h"
#include "common/grpc/async_client_impl.h"
#include "common/http/headers.h"
#include "common/http/utility.h"
#include "common/network/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace ExtAuthz {

// Values used for selecting service paths.
// TODO(gsagula): keep only V2 when V2Alpha gets deprecated.
constexpr char V2[] = "envoy.service.auth_simple.v3.Authorization.Check";

GrpcSimpleClientImpl::GrpcSimpleClientImpl(Grpc::RawAsyncClientPtr&& async_client,
                               const absl::optional<std::chrono::milliseconds>& timeout,
                               bool use_alpha)
    : service_method_(getMethodDescriptor(use_alpha)), async_client_(std::move(async_client)),
      timeout_(timeout) {}

GrpcSimpleClientImpl::~GrpcSimpleClientImpl() { ASSERT(!callbacks_); }

void GrpcSimpleClientImpl::cancel() {
  ASSERT(callbacks_ != nullptr);
  request_->cancel();
  callbacks_ = nullptr;
}

void GrpcSimpleClientImpl::check(RequestCallbacks& callbacks,
                           const envoy::service::auth_simple::v3::CheckRequest& request,
                           Tracing::Span& parent_span, const StreamInfo::StreamInfo&) {
  ASSERT(callbacks_ == nullptr);
  callbacks_ = &callbacks;

  request_ = async_client_->send(service_method_, request, *this, parent_span,
                                 Http::AsyncClient::RequestOptions().setTimeout(timeout_));
}

void GrpcSimpleClientImpl::onSuccess(std::unique_ptr<envoy::service::auth_simple::v3::CheckResponse>&& response,
                               Tracing::Span& span) {
  ResponsePtr authz_response = std::make_unique<Response>(Response{});
  if (response->status().code() == Grpc::Status::WellKnownGrpcStatus::Ok) {
    span.setTag(TracingConstants::get().TraceStatus, TracingConstants::get().TraceOk);
    authz_response->status = CheckStatus::OK;
    // if (response->has_ok_response()) {
    //   toAuthzResponseHeader(authz_response, response->ok_response().headers());
    // }
  // } else {
  //   span.setTag(TracingConstants::get().TraceStatus, TracingConstants::get().TraceUnauthz);
  //   authz_response->status = CheckStatus::Denied;
  //   if (response->has_denied_response()) {
  //     toAuthzResponseHeader(authz_response, response->denied_response().headers());
  //     authz_response->status_code =
  //         static_cast<Http::Code>(response->denied_response().status().code());
  //     authz_response->body = response->denied_response().body();
  //   } else {
  //     authz_response->status_code = Http::Code::Forbidden;
  //   }
  }

  callbacks_->onComplete(std::move(authz_response));
  callbacks_ = nullptr;
}

void GrpcSimpleClientImpl::onFailure(Grpc::Status::GrpcStatus status, const std::string&,
                               Tracing::Span&) {
  ASSERT(status != Grpc::Status::WellKnownGrpcStatus::Ok);
  Response response{};
  response.status = CheckStatus::Error;
  response.status_code = Http::Code::Forbidden;
  callbacks_->onComplete(std::make_unique<Response>(response));
  callbacks_ = nullptr;
}

void GrpcSimpleClientImpl::toAuthzResponseHeader(
    ResponsePtr& response,
    const Protobuf::RepeatedPtrField<envoy::config::core::v3::HeaderValueOption>& headers) {
  for (const auto& header : headers) {
    if (header.append().value()) {
      response->headers_to_append.emplace_back(Http::LowerCaseString(header.header().key()),
                                               header.header().value());
    } else {
      response->headers_to_add.emplace_back(Http::LowerCaseString(header.header().key()),
                                            header.header().value());
    }
  }
}

const Protobuf::MethodDescriptor& GrpcSimpleClientImpl::getMethodDescriptor(bool ) {
  const auto* descriptor = Protobuf::DescriptorPool::generated_pool()->FindMethodByName(V2);
  ASSERT(descriptor != nullptr);
  return *descriptor;
}

} // namespace ExtAuthz
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
