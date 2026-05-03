#include "analysis_types.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace oceandrift::analysis {

// ============================================================================
// XOR key (16 bytes, cycled with index & 0xF)
// ============================================================================
std::array<std::uint8_t, 16> decode_xor_key() {
  return {
      0x8A, 0x4B, 0x2C, 0xD3,
      0xF1, 0xE5, 0x7A, 0x9B,
      0x3D, 0x6F, 0x1C, 0x8E,
      0x5B, 0x2A, 0xD7, 0xC9,
  };
}

// ============================================================================
// decode_hex_xor_payload
//
// Takes a hex-encoded string, converts each 2-char hex pair to a byte via
// strtol(..., 16), then XOR-decrypts the resulting byte buffer with the
// 16-byte cyclic key.  Returns the decrypted plaintext string.
//
// If the input length is odd (i.e. a trailing nibble with no pair) the
// function returns an empty string.
// ============================================================================
std::string decode_hex_xor_payload(const std::string& src)
{
    std::vector<std::uint8_t> raw_bytes;
    std::size_t i = 0;

    /* main loop: walk hex input two characters at a time */
    while (true)
    {
        std::size_t len = src.size();

        /* if we consumed all input, break to XOR phase */
        if (i >= len)
            break;

        /* if only one char remains (odd length), return empty */
        if (i + 1 >= len)
        {
            return {};
        }

        /* extract a 2-character hex substring */
        std::size_t take = 2;
        std::size_t remaining = len - i;
        if (remaining < 2)
            take = remaining;

        std::string hex_pair = src.substr(i, take);

        /* convert hex pair to byte via strtol */
        char* end_ptr = nullptr;
        long value = std::strtol(hex_pair.c_str(), &end_ptr, 16);

        /* strtol consumed nothing  ->  "invalid stoi argument" */
        if (hex_pair.c_str() == end_ptr)
            throw std::invalid_argument("invalid stoi argument");

        /* errno == ERANGE (34)  ->  "stoi argument out of range" */
        if (errno == 34)
            throw std::out_of_range("stoi argument out of range");

        /* append decoded byte to raw buffer */
        raw_bytes.push_back(static_cast<std::uint8_t>(value));

        /* advance by 2 */
        i += 2;
    }

    /* finished hex parse; if nothing was collected, return empty */
    if (raw_bytes.empty())
    {
        return {};
    }

    /* XOR-decrypt phase */
    std::size_t decoded_len = raw_bytes.size();

    /* allocate output buffer */
    std::vector<std::uint8_t> xor_buf(decoded_len, 0);

    /* XOR each byte with key[index & 0xF] */
    for (std::size_t j = 0; j < decoded_len; ++j)
    {
        /* 16-byte XOR key */
        static const auto key = decode_xor_key();
        xor_buf[j] = raw_bytes[j] ^ key[j & 0xF];
    }

    /* build result string from XOR'd buffer */
    std::string result(reinterpret_cast<const char*>(xor_buf.data()), decoded_len);

    /* return decrypted string (move semantics in original via SSO swap) */
    return result;
}

// ============================================================================
// load_config_from_file
//
// Reads a configuration file from disk.  If the content begins with "ENCR:"
// the remainder is treated as hex-encoded, XOR-encrypted data and passed
// through decode_hex_xor_payload.  Otherwise the raw content is used as-is.
//
// The resulting plaintext is parsed as JSON.  The function validates that
// the JSON object contains a "GraphAPI" member.  Returns true on success,
// false on any failure (missing file, empty content, decode failure, missing
// GraphAPI key).
//
// 'this' receives the parsed JSON object on success.
// ============================================================================

using json = nlohmann::json;

bool load_config_from_file(json* self, const std::string& path)
{
    /* build filesystem path and check existence */
    if (!path_exists(path))
    {
        return false;
    }

    /* open file via std::ifstream */
    std::ifstream ifs(path, std::ios::binary);

    /* check stream opened successfully */
    if (!ifs.is_open())
    {
        /* stream teardown, return false */
        return false;
    }

    /* read entire file into file_content string */
    std::string file_content(
        (std::istreambuf_iterator<char>(ifs)),
         std::istreambuf_iterator<char>());

    /* check for read errors */
    /* if content is empty, clean up and return false */
    if (file_content.empty())
    {
        return false;
    }

    /* decrypted_text will hold the final plaintext for JSON parsing */
    std::string decrypted_text;

    /* check for "ENCR:" prefix (5 bytes) */
    bool is_encrypted = false;
    if (file_content.size() >= 5)
    {
        /* extract first 5 chars */
        std::string prefix = file_content.substr(0, 5);

        /* compare against "ENCR:" literal */
        is_encrypted = (prefix == "ENCR:");
    }

    /* branch on encryption flag */
    if (!is_encrypted)
    {
        /* not encrypted: use raw file content as plaintext */
        decrypted_text = file_content;
    }
    else
    {
        /* encrypted path: strip "ENCR:" prefix (5 bytes) */
        std::string hex_payload = file_content.substr(5);

        /* decode hex and XOR-decrypt */
        decrypted_text = decode_hex_xor_payload(hex_payload);

        /* if decode produced empty result, return false */
        if (decrypted_text.empty())
        {
            return false;
        }
    }

    /* parse decrypted text as JSON */
    *self = json::parse(decrypted_text, nullptr, false);

    /* validate that parsed JSON contains "GraphAPI" member */
    if (!self->is_object() || !self->contains("GraphAPI"))
    {
        return false;
    }

    /* success: config loaded and validated */
    return true;
}

// ============================================================================
// Evidence collectors
// ============================================================================

FunctionEvidence decode_hex_xor_evidence() {
  FunctionEvidence out;
  out.address = 0x00424810;
  out.function = "decode_hex_xor_payload";
  out.purpose = "Hex-decodes input string (2 chars -> 1 byte via strtol base-16), "
                "then XOR-decrypts with 16-byte cyclic key at 0x4D6C44";
  out.indicators = {
      "strtol with base 16 for hex pair conversion",
      "XOR key: byte_4D6C44[index & 0xF]  (16-byte cycle)",
      "error path: \"invalid stoi argument\"",
      "error path: \"stoi argument out of range\"",
  };
  return out;
}

FunctionEvidence config_loader_evidence() {
  FunctionEvidence out;
  out.address = 0x00423EC0;
  out.function = "load_config_from_file";
  out.purpose = "Opens config file, detects ENCR: prefix for encrypted configs, "
                "hex+XOR decodes if encrypted, parses JSON, validates GraphAPI key";
  out.indicators = {
      "path_exists check before file open",
      "std::ifstream read of entire file content",
      "input marker: \"ENCR:\"  (5-byte prefix comparison)",
      "decoder call: decode_hex_xor_payload for hex+XOR decryption",
      "JSON parse of decrypted/plaintext content",
      "required JSON member: \"GraphAPI\"",
      "returns false on: missing file, empty content, decode failure, missing GraphAPI",
  };
  return out;
}

}  // namespace oceandrift::analysis
