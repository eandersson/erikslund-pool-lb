#pragma once
// Active TLS leaf-certificate metadata exposed to operators.

#include <cstdint>
#include <string>
#include <vector>

namespace erikslund::core {

struct TlsCertificateStatus {
    std::string listener_name;
    std::int64_t expiry_timestamp_seconds = 0;
};

using TlsCertificateStatuses = std::vector<TlsCertificateStatus>;

} // namespace erikslund::core
