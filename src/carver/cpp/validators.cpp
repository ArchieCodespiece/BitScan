#include "validators.h"
#include <cstring>
#include <algorithm>

namespace CarverNative {

// Helper to find a substring in a binary buffer
static const uint8_t* memmem_custom(const uint8_t* haystack, size_t haystack_len,
                                    const uint8_t* needle, size_t needle_len) {
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len) {
        return nullptr;
    }
    const uint8_t* end = haystack + (haystack_len - needle_len + 1);
    for (const uint8_t* p = haystack; p < end; ++p) {
        if (*p == *needle && memcmp(p, needle, needle_len) == 0) {
            return p;
        }
    }
    return nullptr;
}

ValidationResult FileValidator::validate(const std::string& type, const uint8_t* data, size_t length, bool footer_present) {
    std::string lower_type = type;
    std::transform(lower_type.begin(), lower_type.end(), lower_type.begin(), ::tolower);

    if (lower_type == "jpeg" || lower_type == "jpg") {
        return validate_jpeg(data, length, footer_present);
    } else if (lower_type == "png") {
        return validate_png(data, length, footer_present);
    } else if (lower_type == "pdf") {
        return validate_pdf(data, length, footer_present);
    } else if (lower_type == "gif") {
        return validate_gif(data, length, footer_present);
    } else if (lower_type == "zip" || lower_type == "docx" || lower_type == "xlsx") {
        return validate_zip(data, length, footer_present);
    } else if (lower_type == "bmp") {
        return validate_bmp(data, length, footer_present);
    }
    return validate_generic(data, length, footer_present);
}

ValidationResult FileValidator::validate_jpeg(const uint8_t* data, size_t length, bool footer_present) {
    ValidationResult res = {false, false, false, false, "Too short for JPEG"};
    if (length < 4) return res;

    res.header_ok = (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF);
    res.footer_ok = footer_present && (length >= 2 && data[length - 2] == 0xFF && data[length - 1] == 0xD9);
    res.details = "JPEG Header detected";

    if (res.header_ok) {
        // Check for APP0 (JFIF) or APP1 (Exif) in first 64 bytes
        const uint8_t jfif_tag[] = "JFIF";
        const uint8_t exif_tag[] = "Exif";
        size_t search_len = std::min(length, (size_t)64);
        bool has_jfif = (memmem_custom(data, search_len, jfif_tag, 4) != nullptr);
        bool has_exif = (memmem_custom(data, search_len, exif_tag, 4) != nullptr);

        // Check for SOF markers (\xff\xc0 or \xff\xc2)
        const uint8_t sof0[] = {0xFF, 0xC0};
        const uint8_t sof2[] = {0xFF, 0xC2};
        bool has_sof = (memmem_custom(data, length, sof0, 2) != nullptr) ||
                       (memmem_custom(data, length, sof2, 2) != nullptr);

        if (has_jfif || has_exif || has_sof) {
            res.structure_ok = true;
            res.details = "Valid JPEG markers (JFIF/Exif/SOF) verified";
        }
    }

    res.is_valid = res.header_ok && (res.structure_ok || res.footer_ok || length > 512);
    return res;
}

ValidationResult FileValidator::validate_png(const uint8_t* data, size_t length, bool footer_present) {
    ValidationResult res = {false, false, false, false, "Too short for PNG"};
    const uint8_t png_magic[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    if (length < 8) return res;

    res.header_ok = (memcmp(data, png_magic, 8) == 0);
    const uint8_t iend_magic[8] = {'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82};
    res.footer_ok = footer_present && (length >= 8 && memcmp(data + length - 8, iend_magic, 8) == 0);
    res.details = "PNG header detected";

    if (res.header_ok && length >= 24) {
        // First chunk after signature must be IHDR at offset 12
        if (memcmp(data + 12, "IHDR", 4) == 0) {
            uint32_t width = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
            uint32_t height = (data[20] << 24) | (data[21] << 16) | (data[22] << 8) | data[23];
            if (width > 0 && height > 0) {
                res.structure_ok = true;
                res.details = "Valid PNG IHDR chunk verified";
            }
        }
    }

    res.is_valid = res.header_ok && (res.structure_ok || res.footer_ok);
    return res;
}

ValidationResult FileValidator::validate_pdf(const uint8_t* data, size_t length, bool footer_present) {
    ValidationResult res = {false, false, false, false, "Too short for PDF"};
    if (length < 8) return res;

    res.header_ok = (memcmp(data, "%PDF-", 5) == 0);
    size_t tail_len = std::min(length, (size_t)1024);
    const uint8_t* tail_ptr = data + length - tail_len;
    const uint8_t eof_tag[] = "%%EOF";
    res.footer_ok = footer_present && (memmem_custom(tail_ptr, tail_len, eof_tag, 5) != nullptr);
    res.details = "PDF header detected";

    if (res.header_ok) {
        const uint8_t root_tag[] = "/Root";
        const uint8_t xref_tag[] = "xref";
        const uint8_t startxref_tag[] = "startxref";
        if (memmem_custom(data, length, root_tag, 5) != nullptr ||
            memmem_custom(data, length, xref_tag, 4) != nullptr ||
            memmem_custom(data, length, startxref_tag, 9) != nullptr) {
            res.structure_ok = true;
            res.details = "PDF structural markers (Root/xref/startxref) verified";
        }
    }

    res.is_valid = res.header_ok && (res.structure_ok || res.footer_ok || length > 256);
    return res;
}

ValidationResult FileValidator::validate_gif(const uint8_t* data, size_t length, bool footer_present) {
    ValidationResult res = {false, false, false, false, "Too short for GIF"};
    if (length < 13) return res;

    res.header_ok = (memcmp(data, "GIF87a", 6) == 0 || memcmp(data, "GIF89a", 6) == 0);
    res.footer_ok = footer_present && (data[length - 1] == 0x3B);
    res.details = "GIF header detected";

    if (res.header_ok) {
        uint16_t width = data[6] | (data[7] << 8);
        uint16_t height = data[8] | (data[9] << 8);
        if (width > 0 && height > 0) {
            res.structure_ok = true;
            res.details = "Valid GIF screen descriptor dimensions";
        }
    }

    res.is_valid = res.header_ok && (res.structure_ok || res.footer_ok);
    return res;
}

ValidationResult FileValidator::validate_zip(const uint8_t* data, size_t length, bool footer_present) {
    ValidationResult res = {false, false, false, false, "Too short for ZIP"};
    if (length < 30) return res;

    const uint8_t zip_hdr[4] = {0x50, 0x4B, 0x03, 0x04};
    res.header_ok = (memcmp(data, zip_hdr, 4) == 0);

    const uint8_t eocd_tag[4] = {0x50, 0x4B, 0x05, 0x06};
    size_t tail_len = std::min(length, (size_t)1024);
    const uint8_t* tail_ptr = data + length - tail_len;
    res.footer_ok = footer_present && (memmem_custom(tail_ptr, tail_len, eocd_tag, 4) != nullptr);
    res.structure_ok = res.footer_ok;
    res.details = "ZIP / Archive signature verified";

    res.is_valid = res.header_ok;
    return res;
}

ValidationResult FileValidator::validate_bmp(const uint8_t* data, size_t length, bool footer_present) {
    ValidationResult res = {false, false, false, false, "Too short for BMP"};
    if (length < 26) return res;

    res.header_ok = (data[0] == 'B' && data[1] == 'M');
    res.footer_ok = false;
    res.details = "BMP header detected";

    if (res.header_ok) {
        uint32_t header_size = data[14] | (data[15] << 8) | (data[16] << 16) | (data[17] << 24);
        if (header_size == 12 || header_size == 40 || header_size == 52 ||
            header_size == 56 || header_size == 108 || header_size == 124) {
            res.structure_ok = true;
            res.details = "Valid BMP header size verified";
        }
    }

    res.is_valid = res.header_ok && res.structure_ok;
    return res;
}

ValidationResult FileValidator::validate_generic(const uint8_t* data, size_t length, bool footer_present) {
    ValidationResult res;
    res.header_ok = (length > 0);
    res.footer_ok = footer_present;
    res.structure_ok = false;
    res.details = "Generic signature check passed";
    res.is_valid = res.header_ok;
    return res;
}

double FileValidator::calculate_confidence(const ValidationResult& res, bool size_reasonable, bool is_contiguous) {
    double score = 0.0;
    if (res.header_ok) score += 30.0;
    if (res.footer_ok) score += 20.0;
    if (res.structure_ok) score += 30.0;
    if (size_reasonable) score += 10.0;
    if (is_contiguous) score += 10.0;
    return std::min(score, 100.0);
}

} // namespace CarverNative
