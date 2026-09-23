#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace CarverNative {

struct HashResult {
    std::string md5;
    std::string sha256;
};

class CryptoHasher {
public:
    CryptoHasher();
    ~CryptoHasher();

    bool init();
    HashResult compute_hashes(const uint8_t* data, size_t length);

private:
    void* m_hAlgMd5;
    void* m_hAlgSha256;
    bool m_initialized;
};

} // namespace CarverNative
