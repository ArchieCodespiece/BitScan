#define NOMINMAX
#include "hasher.h"
#include <windows.h>
#include <bcrypt.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

namespace CarverNative {

static std::string bytes_to_hex(const uint8_t* data, size_t length) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

CryptoHasher::CryptoHasher()
    : m_hAlgMd5(nullptr), m_hAlgSha256(nullptr), m_initialized(false) {
    init();
}

CryptoHasher::~CryptoHasher() {
    if (m_hAlgMd5) {
        BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(m_hAlgMd5), 0);
        m_hAlgMd5 = nullptr;
    }
    if (m_hAlgSha256) {
        BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(m_hAlgSha256), 0);
        m_hAlgSha256 = nullptr;
    }
}

bool CryptoHasher::init() {
    if (m_initialized) return true;

    BCRYPT_ALG_HANDLE hMd5 = nullptr;
    BCRYPT_ALG_HANDLE hSha256 = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hMd5, BCRYPT_MD5_ALGORITHM, NULL, 0);
    if (status >= 0) {
        m_hAlgMd5 = hMd5;
    }

    status = BCryptOpenAlgorithmProvider(&hSha256, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status >= 0) {
        m_hAlgSha256 = hSha256;
    }

    m_initialized = (m_hAlgMd5 != nullptr && m_hAlgSha256 != nullptr);
    return m_initialized;
}

HashResult CryptoHasher::compute_hashes(const uint8_t* data, size_t length) {
    HashResult result;
    result.md5 = "";
    result.sha256 = "";

    if (!m_initialized) {
        init();
    }

    // Compute MD5
    if (m_hAlgMd5) {
        BCRYPT_HASH_HANDLE hHash = nullptr;
        NTSTATUS status = BCryptCreateHash(
            static_cast<BCRYPT_ALG_HANDLE>(m_hAlgMd5),
            &hHash, NULL, 0, NULL, 0, 0
        );
        if (status >= 0) {
            BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(length), 0);
            uint8_t hashBuf[16] = {0};
            BCryptFinishHash(hHash, hashBuf, sizeof(hashBuf), 0);
            BCryptDestroyHash(hHash);
            result.md5 = bytes_to_hex(hashBuf, sizeof(hashBuf));
        }
    }

    // Compute SHA256
    if (m_hAlgSha256) {
        BCRYPT_HASH_HANDLE hHash = nullptr;
        NTSTATUS status = BCryptCreateHash(
            static_cast<BCRYPT_ALG_HANDLE>(m_hAlgSha256),
            &hHash, NULL, 0, NULL, 0, 0
        );
        if (status >= 0) {
            BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(length), 0);
            uint8_t hashBuf[32] = {0};
            BCryptFinishHash(hHash, hashBuf, sizeof(hashBuf), 0);
            BCryptDestroyHash(hHash);
            result.sha256 = bytes_to_hex(hashBuf, sizeof(hashBuf));
        }
    }

    return result;
}

} // namespace CarverNative
