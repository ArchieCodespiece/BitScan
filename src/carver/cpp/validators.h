#pragma once

#include <string>
#include <cstdint>
#include <cstddef>

namespace CarverNative {

struct ValidationResult {
    bool is_valid;
    bool header_ok;
    bool footer_ok;
    bool structure_ok;
    std::string details;
};

class FileValidator {
public:
    static ValidationResult validate(const std::string& type, const uint8_t* data, size_t length, bool footer_present);
    static double calculate_confidence(const ValidationResult& res, bool size_reasonable = true, bool is_contiguous = true);

    // Format-specific exact boundary locators
    static bool find_zip_boundary(const uint8_t* data, size_t length, size_t& out_size);
    static bool find_pdf_boundary(const uint8_t* data, size_t length, size_t& out_size);
    static bool find_jpeg_boundary(const uint8_t* data, size_t length, size_t& out_size);
    static bool find_png_boundary(const uint8_t* data, size_t length, size_t& out_size);

private:
    static ValidationResult validate_jpeg(const uint8_t* data, size_t length, bool footer_present);
    static ValidationResult validate_png(const uint8_t* data, size_t length, bool footer_present);
    static ValidationResult validate_pdf(const uint8_t* data, size_t length, bool footer_present);
    static ValidationResult validate_gif(const uint8_t* data, size_t length, bool footer_present);
    static ValidationResult validate_zip(const uint8_t* data, size_t length, bool footer_present);
    static ValidationResult validate_bmp(const uint8_t* data, size_t length, bool footer_present);
    static ValidationResult validate_generic(const uint8_t* data, size_t length, bool footer_present);
};

} // namespace CarverNative
