#include "sanitizer.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <io.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <sys/sysmacros.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <limits.h>
#endif
#endif

namespace {
constexpr size_t kDefaultBuffer = 4 * 1024 * 1024;

void set_text(char* out, size_t capacity, const std::string& text) {
    if (!out || capacity == 0) return;
    const size_t count = std::min(capacity - 1, text.size());
    std::memcpy(out, text.data(), count);
    out[count] = '\0';
}

#ifdef _WIN32
std::wstring widen(const char* utf8) {
    if (!utf8) return {};
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, nullptr, 0);
    if (needed <= 0) return {};
    std::wstring result(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, result.data(), needed);
    result.resize(static_cast<size_t>(needed - 1));
    return result;
}

class NativeFile {
public:
    explicit NativeFile(const char* path) {
        const auto wide_path = widen(path);
        if (!wide_path.empty()) {
            handle_ = CreateFileW(wide_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr);
        }
    }
    ~NativeFile() { if (valid()) CloseHandle(handle_); }
    bool valid() const { return handle_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const { return handle_; }
    bool size(uint64_t& out) const {
        LARGE_INTEGER value{};
        if (!GetFileSizeEx(handle_, &value) || value.QuadPart < 0) return false;
        out = static_cast<uint64_t>(value.QuadPart);
        return true;
    }
    bool read_at(uint64_t offset, uint8_t* data, size_t length) const {
        size_t done = 0;
        while (done < length) {
            LARGE_INTEGER pos{};
            pos.QuadPart = static_cast<LONGLONG>(offset + done);
            if (!SetFilePointerEx(handle_, pos, nullptr, FILE_BEGIN)) return false;
            const DWORD request = static_cast<DWORD>(std::min<size_t>(length - done, MAXDWORD));
            DWORD actual = 0;
            if (!ReadFile(handle_, data + done, request, &actual, nullptr) || actual == 0) return false;
            done += actual;
        }
        return true;
    }
    bool write_at(uint64_t offset, const uint8_t* data, size_t length) const {
        size_t done = 0;
        while (done < length) {
            LARGE_INTEGER pos{};
            pos.QuadPart = static_cast<LONGLONG>(offset + done);
            if (!SetFilePointerEx(handle_, pos, nullptr, FILE_BEGIN)) return false;
            const DWORD request = static_cast<DWORD>(std::min<size_t>(length - done, MAXDWORD));
            DWORD actual = 0;
            if (!WriteFile(handle_, data + done, request, &actual, nullptr) || actual == 0) return false;
            done += actual;
        }
        return true;
    }
    bool flush() const { return FlushFileBuffers(handle_) != 0; }
    bool is_regular_file() const {
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(handle_, &info)) return false;
        return (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
    }
    bool truncate_zero() const {
        LARGE_INTEGER zero{};
        return SetFilePointerEx(handle_, zero, nullptr, FILE_BEGIN) && SetEndOfFile(handle_);
    }
private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

bool target_is_system_disk(const char* target_path) {
    const std::wstring target = widen(target_path);
    if (target.empty()) return true;
    HANDLE target_handle = CreateFileW(target.c_str(), 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (target_handle == INVALID_HANDLE_VALUE) return false;
    STORAGE_DEVICE_NUMBER target_number{};
    DWORD returned = 0;
    const bool target_ok = DeviceIoControl(target_handle, IOCTL_STORAGE_GET_DEVICE_NUMBER,
        nullptr, 0, &target_number, sizeof(target_number), &returned, nullptr) != 0;
    CloseHandle(target_handle);
    if (!target_ok) return false;

    wchar_t windows_dir[MAX_PATH]{};
    if (GetWindowsDirectoryW(windows_dir, MAX_PATH) == 0) return false;
    wchar_t system_volume[MAX_PATH]{};
    if (!GetVolumePathNameW(windows_dir, system_volume, MAX_PATH)) return false;
    std::wstring system_device = L"\\\\.\\";
    system_device.push_back(system_volume[0]);
    system_device.push_back(L':');
    HANDLE system_handle = CreateFileW(system_device.c_str(), 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (system_handle == INVALID_HANDLE_VALUE) return false;
    STORAGE_DEVICE_NUMBER system_number{};
    const bool system_ok = DeviceIoControl(system_handle, IOCTL_STORAGE_GET_DEVICE_NUMBER,
        nullptr, 0, &system_number, sizeof(system_number), &returned, nullptr) != 0;
    CloseHandle(system_handle);
    return system_ok && target_number.DeviceNumber == system_number.DeviceNumber;
}
#else
class NativeFile {
public:
    explicit NativeFile(const char* path) : fd_(path ? open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW) : -1) {}
    ~NativeFile() { if (fd_ >= 0) close(fd_); }
    bool valid() const { return fd_ >= 0; }
    int get() const { return fd_; }
    bool size(uint64_t& out) const {
        struct stat info{};
        if (fstat(fd_, &info) != 0) return false;
#ifdef __linux__
        if (S_ISBLK(info.st_mode)) {
            unsigned long long bytes = 0;
            if (ioctl(fd_, BLKGETSIZE64, &bytes) != 0) return false;
            out = static_cast<uint64_t>(bytes);
            return true;
        }
#endif
        if (info.st_size < 0) return false;
        out = static_cast<uint64_t>(info.st_size);
        return true;
    }
    bool read_at(uint64_t offset, uint8_t* data, size_t length) const {
        size_t done = 0;
        while (done < length) {
            const ssize_t n = pread(fd_, data + done, length - done, static_cast<off_t>(offset + done));
            if (n <= 0) return false;
            done += static_cast<size_t>(n);
        }
        return true;
    }
    bool write_at(uint64_t offset, const uint8_t* data, size_t length) const {
        size_t done = 0;
        while (done < length) {
            const ssize_t n = pwrite(fd_, data + done, length - done, static_cast<off_t>(offset + done));
            if (n <= 0) return false;
            done += static_cast<size_t>(n);
        }
        return true;
    }
    bool flush() const { return fsync(fd_) == 0; }
    bool is_regular_file() const {
        struct stat info{};
        return fstat(fd_, &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 1;
    }
    bool truncate_zero() const { return ftruncate(fd_, 0) == 0; }
private:
    int fd_ = -1;
};

bool target_is_system_disk(const char* target_path) {
#ifdef __linux__
    struct stat target_info{};
    if (stat(target_path, &target_info) != 0 || !S_ISBLK(target_info.st_mode)) return false;
    struct stat root_info{};
    if (stat("/", &root_info) != 0) return true;
    if (major(target_info.st_rdev) == major(root_info.st_dev) &&
        minor(target_info.st_rdev) == minor(root_info.st_dev)) return true;

    char target_link[PATH_MAX]{};
    char root_link[PATH_MAX]{};
    const std::string target_sys = "/sys/dev/block/" +
        std::to_string(major(target_info.st_rdev)) + ":" + std::to_string(minor(target_info.st_rdev));
    const std::string root_sys = "/sys/dev/block/" +
        std::to_string(major(root_info.st_dev)) + ":" + std::to_string(minor(root_info.st_dev));
    if (!realpath(target_sys.c_str(), target_link) || !realpath(root_sys.c_str(), root_link)) return true;
    const std::string target_real(target_link);
    const std::string root_real(root_link);
    if (root_real.size() > target_real.size() &&
        root_real.compare(0, target_real.size(), target_real) == 0 &&
        root_real[target_real.size()] == '/') return true;

    // A device currently mounted anywhere, or containing a mounted partition,
    // is not a safe sanitization target.
    std::ifstream mounts("/proc/self/mounts");
    std::string source, mountpoint, rest;
    while (mounts >> source >> mountpoint) {
        std::getline(mounts, rest);
        struct stat mounted_info{};
        if (stat(source.c_str(), &mounted_info) == 0 && S_ISBLK(mounted_info.st_mode)) {
            if (mounted_info.st_rdev == target_info.st_rdev) return true;
            const std::string mounted_sys = "/sys/dev/block/" +
                std::to_string(major(mounted_info.st_rdev)) + ":" + std::to_string(minor(mounted_info.st_rdev));
            char mounted_link[PATH_MAX]{};
            if (realpath(mounted_sys.c_str(), mounted_link)) {
                const std::string mounted_real(mounted_link);
                if (mounted_real.size() > target_real.size() &&
                    mounted_real.compare(0, target_real.size(), target_real) == 0 &&
                    mounted_real[target_real.size()] == '/') return true;
            }
        }
    }
#else
    (void)target_path;
#endif
    return false;
}
#endif

std::string last_error(const char* action) {
#ifdef _WIN32
    return std::string(action) + " (Windows error " + std::to_string(GetLastError()) + ")";
#else
    return std::string(action) + ": " + std::strerror(errno);
#endif
}

std::string sha256_file(const NativeFile& file, uint64_t length) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    std::string result;
    std::vector<uint8_t> buffer(kDefaultBuffer);
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1) {
        uint64_t offset = 0;
        bool ok = true;
        while (offset < length) {
            const size_t count = static_cast<size_t>(std::min<uint64_t>(buffer.size(), length - offset));
            if (!file.read_at(offset, buffer.data(), count) || EVP_DigestUpdate(ctx, buffer.data(), count) != 1) {
                ok = false;
                break;
            }
            offset += count;
        }
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int digest_size = 0;
        if (ok && EVP_DigestFinal_ex(ctx, digest.data(), &digest_size) == 1) {
            static const char hex[] = "0123456789abcdef";
            result.reserve(digest_size * 2);
            for (unsigned int i = 0; i < digest_size; ++i) {
                result.push_back(hex[digest[i] >> 4]);
                result.push_back(hex[digest[i] & 0x0f]);
            }
        }
    }
    EVP_MD_CTX_free(ctx);
    return result;
}

bool fill_pattern(std::vector<uint8_t>& buffer, int pattern) {
    if (pattern == 0) {
        std::fill(buffer.begin(), buffer.end(), 0);
        return true;
    }
    if (pattern == 1) {
        std::fill(buffer.begin(), buffer.end(), 0xff);
        return true;
    }
    return buffer.size() <= static_cast<size_t>(INT_MAX) &&
        RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) == 1;
}

void emit(BSEventCallback callback, const char* event, int index, int total,
          int64_t bytes, int64_t start, int64_t end, int verified, const char* message) {
    if (callback) callback(event, index, total, bytes, start, end, verified, message ? message : "");
}

bool write_range(NativeFile& file, uint64_t start, uint64_t length, int pattern,
                 bool verify, size_t chunk_size, uint64_t& progress, uint64_t total_work,
                 BSProgressCallback progress_callback, BSCancelCallback cancel_callback,
                 std::string& error) {
    std::vector<uint8_t> data(std::max<size_t>(1, chunk_size));
    std::vector<uint8_t> check(data.size());
    uint64_t done = 0;
    while (done < length) {
        if (cancel_callback && cancel_callback()) {
            error = "Sanitization cancelled by operator.";
            return false;
        }
        const size_t count = static_cast<size_t>(std::min<uint64_t>(data.size(), length - done));
        if (count != data.size()) data.resize(count), check.resize(count);
        if (!fill_pattern(data, pattern)) {
            error = "Cryptographic random generator failed.";
            return false;
        }
        if (!file.write_at(start + done, data.data(), count)) {
            error = last_error("Write failed");
            return false;
        }
        if (verify) {
            if (!file.flush() || !file.read_at(start + done, check.data(), count) ||
                !std::equal(data.begin(), data.end(), check.begin())) {
                error = "Readback verification failed.";
                return false;
            }
        }
        done += count;
        progress += count;
        if (progress_callback) progress_callback(static_cast<int64_t>(progress), static_cast<int64_t>(total_work));
        if (count != data.size()) data.resize(std::max<size_t>(1, chunk_size)), check.resize(data.size());
    }
    return true;
}
} // namespace

BS_API int BS_ShredFile(const char* utf8_path, int method, size_t buffer_size,
                        BSEventCallback event_callback, BSShredResult* result) {
    if (!result) return 0;
    std::memset(result, 0, sizeof(*result));
    const auto started = std::chrono::steady_clock::now();
    if (!utf8_path || (method != 0 && method != 1)) {
        set_text(result->error, sizeof(result->error), "Invalid file shred request.");
        return 0;
    }
    NativeFile file(utf8_path);
    if (!file.valid()) {
        set_text(result->error, sizeof(result->error), last_error("Unable to open target file"));
        return 0;
    }
    if (!file.is_regular_file()) {
        set_text(result->error, sizeof(result->error), "Only a regular, single-link file can be shredded.");
        return 0;
    }
    uint64_t size = 0;
    if (!file.size(size) || size > static_cast<uint64_t>(INT64_MAX)) {
        set_text(result->error, sizeof(result->error), "Unable to determine target file size.");
        return 0;
    }
    result->size_before = static_cast<int64_t>(size);
    result->passes = method == 1 ? 3 : 1;
    const std::string before = sha256_file(file, size);
    set_text(result->sha256_before, sizeof(result->sha256_before), before);
    if (size > 0 && before.empty()) {
        set_text(result->error, sizeof(result->error), "Unable to hash target file before overwrite.");
        return 0;
    }

    const size_t block_size = std::clamp(buffer_size ? buffer_size : kDefaultBuffer,
                                         static_cast<size_t>(4096), kDefaultBuffer);
    const int patterns[] = {method == 1 ? 0 : 2, 1, 2};
    uint64_t bytes_written_total = 0;
    bool all_verified = true;
    for (int pass = 0; pass < result->passes; ++pass) {
        std::vector<uint8_t> data(block_size), check(block_size);
        uint64_t offset = 0;
        while (offset < size) {
            const size_t count = static_cast<size_t>(std::min<uint64_t>(block_size, size - offset));
            data.resize(count);
            check.resize(count);
            if (!fill_pattern(data, patterns[pass])) {
                set_text(result->error, sizeof(result->error), "Cryptographic random generator failed.");
                return 0;
            }
            if (!file.write_at(offset, data.data(), count)) {
                set_text(result->error, sizeof(result->error), last_error("File overwrite failed"));
                return 0;
            }
            if (!file.flush() || !file.read_at(offset, check.data(), count) ||
                !std::equal(data.begin(), data.end(), check.begin())) {
                all_verified = false;
                set_text(result->error, sizeof(result->error), "File readback verification failed.");
                return 0;
            }
            offset += count;
            bytes_written_total += count;
        }
        if (!file.flush()) {
            set_text(result->error, sizeof(result->error), last_error("Unable to flush overwritten file"));
            return 0;
        }
        emit(event_callback, "pass_complete", pass + 1, result->passes,
             static_cast<int64_t>(size), 0, static_cast<int64_t>(size), 1,
             method == 1 ? (pass == 0 ? "Binary zeros (0x00)" : pass == 1 ? "Binary ones (0xFF)" : "CSPRNG random") : "CSPRNG random");
    }

    const std::string after = sha256_file(file, size);
    set_text(result->sha256_after, sizeof(result->sha256_after), after);
    if (size > 0 && after.empty()) {
        set_text(result->error, sizeof(result->error), "Unable to hash overwritten file.");
        return 0;
    }
    if (!file.truncate_zero() || !file.flush()) {
        set_text(result->error, sizeof(result->error), last_error("Unable to truncate overwritten file"));
        return 0;
    }
    result->size_after = 0;
#ifdef _WIN32
    const auto wide_path = widen(utf8_path);
    if (wide_path.empty() || _wunlink(wide_path.c_str()) != 0) {
        set_text(result->error, sizeof(result->error), "Overwritten file could not be unlinked.");
        return 0;
    }
#else
    if (unlink(utf8_path) != 0) {
        set_text(result->error, sizeof(result->error), last_error("Overwritten file could not be unlinked"));
        return 0;
    }
#endif
    result->success = 1;
    result->verified = all_verified ? 1 : 0;
    set_text(result->note, sizeof(result->note), "Overwritten and readback-verified; filesystem metadata and flash remapping are outside this operation's guarantee.");
    emit(event_callback, "scrub", 0, 0, static_cast<int64_t>(bytes_written_total), 0, 0,
         result->verified, "File truncated and unlinked; metadata cleanup is best-effort.");
    result->duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    return 1;
}

BS_API int BS_SanitizeDrive(const char* utf8_path, const char* confirmation,
                            uint64_t requested_size, int method, int verify,
                            BSProgressCallback progress_callback,
                            BSCancelCallback cancel_callback,
                            char* error, size_t error_capacity) {
    if (error && error_capacity) error[0] = '\0';
    if (!utf8_path || !confirmation || std::strcmp(utf8_path, confirmation) != 0 ||
        requested_size == 0 || method < 0 || method > 3) {
        set_text(error, error_capacity, "Invalid request: exact target confirmation, known capacity, and a supported method are required.");
        return 0;
    }
    if (target_is_system_disk(utf8_path)) {
        set_text(error, error_capacity, "Refusing to sanitize a mounted or system disk.");
        return 0;
    }
    NativeFile file(utf8_path);
    if (!file.valid()) {
        set_text(error, error_capacity, last_error("Unable to open target device"));
        return 0;
    }
    uint64_t actual_size = 0;
    if (!file.size(actual_size) || actual_size == 0 || requested_size != actual_size) {
        set_text(error, error_capacity, "Target capacity is unavailable or changed since selection; refusing to write.");
        return 0;
    }
    const size_t chunk_size = kDefaultBuffer;
    uint64_t total_work = 0;
    if (method == 3) {
        const uint64_t edge = std::min<uint64_t>(10 * 1024 * 1024, actual_size);
        total_work = edge + (actual_size > edge ? std::min<uint64_t>(edge, actual_size - edge) : 0);
    } else {
        const int passes = method == 1 ? 3 : 1;
        total_work = actual_size * static_cast<uint64_t>(passes) * (verify ? 2 : 1);
    }
    uint64_t progress = 0;
    std::string failure;
    auto run_pass = [&](int pattern, uint64_t start, uint64_t length) -> bool {
        if (!write_range(file, start, length, pattern, verify != 0, chunk_size,
                         progress, total_work, progress_callback, cancel_callback, failure)) return false;
        return file.flush() || (failure = last_error("Unable to flush target device"), false);
    };

    bool ok = true;
    if (method == 3) {
        const uint64_t edge = std::min<uint64_t>(10 * 1024 * 1024, actual_size);
        ok = run_pass(0, 0, edge);
        const uint64_t tail_start = actual_size > edge ? actual_size - std::min<uint64_t>(edge, actual_size - edge) : actual_size;
        if (ok && tail_start >= edge && actual_size > edge) ok = run_pass(0, tail_start, actual_size - tail_start);
    } else {
        const int passes[] = {method == 1 ? 0 : method == 0 ? 0 : 2, 1, 2};
        const int count = method == 1 ? 3 : 1;
        for (int pass = 0; pass < count && ok; ++pass) {
            ok = run_pass(passes[pass], 0, actual_size);
        }
    }
    if (!ok) {
        set_text(error, error_capacity, failure.empty() ? "Sanitization failed." : failure);
        return 0;
    }
    if (progress_callback) progress_callback(static_cast<int64_t>(total_work), static_cast<int64_t>(total_work));
    return 1;
}
