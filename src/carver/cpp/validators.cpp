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

bool FileValidator::find_jpeg_boundary(const uint8_t* data, size_t length, size_t& out_size) {
    if (!data || length < 4) return false;
    if (data[0] != 0xFF || data[1] != 0xD8) return false;

    size_t idx = 2;
    while (idx < length) {
        // Fast skip non-0xFF entropy bytes
        if (data[idx] != 0xFF) {
            while (idx < length && data[idx] != 0xFF) {
                idx++;
            }
            if (idx >= length) break;
        }

        // Skip 0xFF fill bytes
        while (idx < length && data[idx] == 0xFF) {
            idx++;
        }
        if (idx >= length) break;

        uint8_t marker = data[idx++];

        if (marker == 0x00) {
            // Byte-stuffed 0xFF inside entropy-coded scan
            continue;
        } else if (marker >= 0xD0 && marker <= 0xD7) {
            // Restart marker RST0-RST7 (no payload)
            continue;
        } else if (marker == 0xD9) {
            // End of Image (EOI)
            out_size = idx;
            return true;
        } else if (marker == 0xD8) {
            // Next Start of Image (SOI) - previous image ended without clean EOI
            out_size = (idx >= 2) ? (idx - 2) : 0;
            return true;
        } else {
            // Variable-length marker segment (APPn, SOFn, DQT, DHT, SOS, COM, etc.)
            if (idx + 2 > length) break;
            uint16_t seg_len = (static_cast<uint16_t>(data[idx]) << 8) | data[idx + 1];
            if (seg_len < 2) break;
            idx += seg_len;
        }
    }

    return false;
}

bool FileValidator::find_png_boundary(const uint8_t* data, size_t length, size_t& out_size) {
    if (!data || length < 8) return false;
    const uint8_t png_magic[8] = {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    if (memcmp(data, png_magic, 8) != 0) return false;

    size_t idx = 8;
    while (idx + 8 <= length) {
        uint32_t chunk_len = (static_cast<uint32_t>(data[idx]) << 24) |
                             (static_cast<uint32_t>(data[idx + 1]) << 16) |
                             (static_cast<uint32_t>(data[idx + 2]) << 8) |
                             static_cast<uint32_t>(data[idx + 3]);
        if (chunk_len > 100 * 1024 * 1024) break;

        const uint8_t* chunk_type = data + idx + 4;
        size_t total_chunk = 8 + static_cast<size_t>(chunk_len) + 4;
        if (idx + total_chunk > length) break;

        idx += total_chunk;
        if (memcmp(chunk_type, "IEND", 4) == 0) {
            out_size = idx;
            return true;
        }
    }

    // Fallback: search for IEND chunk signature
    const uint8_t iend_sig[8] = {'I', 'E', 'N', 'D', 0xAE, 0x42, 0x60, 0x82};
    const uint8_t* p = memmem_custom(data, length, iend_sig, 8);
    if (p) {
        out_size = (p - data) + 8;
        return true;
    }

    return false;
}

bool FileValidator::find_zip_boundary(const uint8_t* data, size_t length, size_t& out_size) {
    if (!data || length < 22) return false;

    // Search backwards for PK\x05\x06 (EOCD signature 0x06054b50)
    for (int64_t i = static_cast<int64_t>(length) - 22; i >= 0; --i) {
        if (data[i] == 0x50 && data[i+1] == 0x4B && data[i+2] == 0x05 && data[i+3] == 0x06) {
            size_t eocd_pos = static_cast<size_t>(i);

            uint16_t disk_no = data[eocd_pos + 4] | (data[eocd_pos + 5] << 8);
            uint16_t cd_disk = data[eocd_pos + 6] | (data[eocd_pos + 7] << 8);
            uint16_t total_entries = data[eocd_pos + 10] | (data[eocd_pos + 11] << 8);
            uint32_t cd_size = data[eocd_pos + 12] | (data[eocd_pos + 13] << 8) |
                               (data[eocd_pos + 14] << 16) | (data[eocd_pos + 15] << 24);
            uint32_t cd_offset = data[eocd_pos + 16] | (data[eocd_pos + 17] << 8) |
                                 (data[eocd_pos + 18] << 16) | (data[eocd_pos + 19] << 24);
            uint16_t comment_len = data[eocd_pos + 20] | (data[eocd_pos + 21] << 8);

            // Verification: single-volume archive must have disk_no == 0 and cd_disk == 0
            // and cd_offset + cd_size <= eocd_pos
            if (disk_no == 0 && cd_disk == 0 && (static_cast<uint64_t>(cd_offset) + cd_size <= eocd_pos)) {
                if (total_entries > 0) {
                    if (cd_offset + 4 <= length &&
                        data[cd_offset] == 0x50 && data[cd_offset + 1] == 0x4B &&
                        data[cd_offset + 2] == 0x01 && data[cd_offset + 3] == 0x02) {
                        size_t exact_len = eocd_pos + 22 + comment_len;
                        out_size = std::min(exact_len, length);
                        return true;
                    }
                } else if (total_entries == 0 && cd_size == 0) {
                    size_t exact_len = eocd_pos + 22 + comment_len;
                    out_size = std::min(exact_len, length);
                    return true;
                }
            }
        }
    }
    return false;
}

bool FileValidator::find_pdf_boundary(const uint8_t* data, size_t length, size_t& out_size) {
    if (!data || length < 8) return false;
    if (memcmp(data, "%PDF-", 5) != 0 && memcmp(data, "%PDF", 4) != 0) return false;

    // Search backwards from the end for %%EOF (0x25, 0x25, 0x45, 0x4F, 0x46)
    // To handle incremental updates and revisions, take the LAST valid %%EOF
    for (int64_t i = static_cast<int64_t>(length) - 5; i >= 0; --i) {
        if (data[i] == '%' && data[i+1] == '%' && data[i+2] == 'E' && data[i+3] == 'O' && data[i+4] == 'F') {
            size_t eof_pos = static_cast<size_t>(i);

            // Check preceding context: startxref, xref, trailer, or endobj within 2048 bytes
            size_t check_start = (eof_pos > 2048) ? (eof_pos - 2048) : 0;
            size_t check_len = eof_pos - check_start;

            const uint8_t startxref_tag[] = "startxref";
            const uint8_t xref_tag[] = "xref";
            const uint8_t trailer_tag[] = "trailer";
            const uint8_t endobj_tag[] = "endobj";

            bool valid_trailer = (memmem_custom(data + check_start, check_len, startxref_tag, 9) != nullptr) ||
                                 (memmem_custom(data + check_start, check_len, xref_tag, 4) != nullptr) ||
                                 (memmem_custom(data + check_start, check_len, trailer_tag, 7) != nullptr) ||
                                 (memmem_custom(data + check_start, check_len, endobj_tag, 6) != nullptr);

            if (valid_trailer) {
                // Include trailing newlines and whitespace after %%EOF
                size_t end_pos = eof_pos + 5;
                while (end_pos < length && (data[end_pos] == '\r' || data[end_pos] == '\n' || data[end_pos] == ' ' || data[end_pos] == '\t')) {
                    end_pos++;
                }
                out_size = end_pos;
                return true;
            }
        }
    }

    return false;
}

ValidationResult FileValidator::validate_pdf(const uint8_t* data, size_t length, bool footer_present) {
    ValidationResult res = {false, false, false, false, "Too short for PDF"};
    if (length < 8) return res;

    res.header_ok = (memcmp(data, "%PDF-", 5) == 0) || (memcmp(data, "%PDF", 4) == 0);
    size_t tail_len = std::min(length, (size_t)2048);
    const uint8_t* tail_ptr = data + length - tail_len;
    const uint8_t eof_tag[] = "%%EOF";
    res.footer_ok = footer_present || (memmem_custom(tail_ptr, tail_len, eof_tag, 5) != nullptr);
    res.details = "PDF header detected";

    if (res.header_ok) {
        const uint8_t root_tag[] = "/Root";
        const uint8_t xref_tag[] = "xref";
        const uint8_t startxref_tag[] = "startxref";
        const uint8_t pages_tag[] = "/Pages";
        if (memmem_custom(data, length, root_tag, 5) != nullptr ||
            memmem_custom(data, length, xref_tag, 4) != nullptr ||
            memmem_custom(data, length, startxref_tag, 9) != nullptr ||
            memmem_custom(data, length, pages_tag, 6) != nullptr) {
            res.structure_ok = true;
            res.details = "PDF structural markers (/Root, /Pages, xref, startxref) verified";
        }
    }

    res.is_valid = res.header_ok && (res.structure_ok || res.footer_ok);
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
    if (length < 22) return res;

    const uint8_t zip_hdr[4] = {0x50, 0x4B, 0x03, 0x04};
    res.header_ok = (memcmp(data, zip_hdr, 4) == 0);

    size_t boundary_sz = 0;
    if (find_zip_boundary(data, length, boundary_sz)) {
        res.footer_ok = true;
        res.structure_ok = true;
        res.details = "Verified complete ZIP archive with intact EOCD and central directory";
    } else {
        const uint8_t eocd_tag[4] = {0x50, 0x4B, 0x05, 0x06};
        size_t tail_len = std::min(length, (size_t)65557);
        const uint8_t* tail_ptr = data + length - tail_len;
        res.footer_ok = footer_present || (memmem_custom(tail_ptr, tail_len, eocd_tag, 4) != nullptr);
        res.structure_ok = res.footer_ok;
        res.details = res.footer_ok ? "ZIP EOCD detected" : "Missing ZIP EOCD record";
    }

    res.is_valid = res.header_ok && (res.structure_ok || res.footer_ok);
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
