#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <cstring>
#include <numeric>
#include <algorithm>
#include <filesystem>
#include <cstddef>
#include <array>
#include <zlib.h>

extern "C" {
#include "c/LzmaDec.h" // Ensure this path is correct for your LZMA SDK
}

struct Crc32TableHolder {
    std::array<uint32_t, 256> table;

    Crc32TableHolder() {
        const uint32_t poly = 0xEDB88320;

        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t crc_entry = i;
            for (int j = 0; j < 8; ++j) {
                if (crc_entry & 1) {
                    crc_entry = (crc_entry >> 1) ^ poly;
                } else {
                    crc_entry = crc_entry >> 1;
                }
            }
            table[i] = crc_entry;
        }
    }
};

inline static uint32_t compute_crc32(const std::vector<uint8_t>& buf, uint32_t initial_crc = 0) {
    static const Crc32TableHolder crc_table_holder;

    uint32_t crc = ~initial_crc;

    for (long long i = 0; i < buf.size(); ++i) {
        uint8_t byte = buf[i];
        crc = crc_table_holder.table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }

    return ~crc;
}

inline static void xor_crypt(std::vector<uint8_t>& buffer, uint32_t key) {
    if (buffer.empty()) return;
    uint8_t key_bytes[4];
    memcpy(key_bytes, &key, 4);
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] ^= key_bytes[i & 3]; // i % 4
    }
}

// UCL Decompression STUB
inline static bool decompress_ucl(const std::vector<uint8_t>& in_buffer, std::vector<uint8_t>& out_buffer, uint32_t expected_out_size) {
    out_buffer = std::vector<uint8_t>(expected_out_size);
    std::cerr << "[WARN] UCL decompression is a STUB. File content for UCL compressed files will be INCORRECT." << std::endl;
    if (expected_out_size == 0) return true;
    if (in_buffer.size() == 0 && expected_out_size > 0) return false;
    if (in_buffer.size() == 0 && expected_out_size == 0) return true;

    size_t to_copy = std::min(in_buffer.size(), static_cast<size_t>(expected_out_size));
    memcpy(out_buffer.data(), in_buffer.data(), to_copy);
    if (to_copy < expected_out_size) {
        memset(out_buffer.data() + to_copy, 0, expected_out_size - to_copy);
    }
    return false;
}

// Idk if it works
inline static bool decompress_zlib(const std::vector<uint8_t>& in_buffer, std::vector<uint8_t>& out_buffer, uint32_t expected_out_size) {
    out_buffer = std::vector<uint8_t>(expected_out_size);
    if (expected_out_size == 0) return true;
    if (in_buffer.size() == 0) return false;

    z_stream strm = {};
    strm.avail_in = static_cast<uInt>(in_buffer.size());
    strm.next_in = (Bytef*)in_buffer.data();
    strm.avail_out = static_cast<uInt>(expected_out_size);
    strm.next_out = (Bytef*)out_buffer.data();

    if (inflateInit(&strm) != Z_OK) {
        std::cerr << "ZLIB: inflateInit failed: " << (strm.msg ? strm.msg : "unknown error") << std::endl;
        out_buffer.clear();
        return false;
    }

    int ret = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);

    if (ret != Z_STREAM_END) {
        std::cerr << "ZLIB: inflate failed with code " << ret << " (" << (strm.msg ? strm.msg : "unknown error") << "). "
            << "Output size: " << strm.total_out << "/" << expected_out_size << std::endl;
        return false;
    }
    if (strm.total_out != expected_out_size) {
        std::cerr << "ZLIB: output size mismatch. Got " << strm.total_out << ", expected " << expected_out_size << std::endl;
        out_buffer.clear();
        return false;
    }
    return true;
}

// LZMA SDK Memory Allocation Callbacks
void* SzAlloc(ISzAllocPtr, size_t size) { return malloc(size); }
void SzFree(ISzAllocPtr, void* address) { free(address); }
ISzAlloc g_LzmaAlloc = { SzAlloc, SzFree };

// Works
inline static bool decompress_lzma(std::vector<uint8_t>& in_buffer, std::vector<uint8_t>& out_buffer, uint32_t expected_out_size) {
    out_buffer = std::vector<uint8_t>(expected_out_size);
    if (expected_out_size == 0) return true;
    if (in_buffer.size() < LZMA_PROPS_SIZE) {
        std::cerr << "LZMA: Input buffer too small for properties (" << in_buffer.size() << " < " << LZMA_PROPS_SIZE << ")." << std::endl;
        return false;
    }

    CLzmaDec state;
    state.dic = NULL;
    state.probs = NULL;
    if (LzmaDec_Allocate(&state, reinterpret_cast<const Byte*>(in_buffer.data()), LZMA_PROPS_SIZE, &g_LzmaAlloc) != SZ_OK) {
        std::cerr << "LZMA: LzmaDec_Allocate failed." << std::endl;
        return false;
    }

    // Set the output dictionary buffer information in the state.
    // This MUST be done AFTER LzmaDec_Allocate, as LzmaDec_Construct (called by Allocate)
    // will zero out state.dic and state.dicBufSize.
    free(state.dic);
    state.dic = out_buffer.data();
    state.dicBufSize = expected_out_size;

    // Initialize/reset the decoder's core state (RangeCoder, etc.) for a new stream.
    LzmaDec_Init(&state);

    // srcLen is an in/out parameter.
    // Input:  Number of bytes available in the source buffer (payload part).
    // Output: (As per user's provided LzmaDec_DecodeToDic source) Number of bytes *consumed* from the source.
    SizeT src_len_payload = in_buffer.size() - LZMA_PROPS_SIZE;
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;

    // dicLimit should be the total capacity of the output buffer `state.dic`.
    // LzmaDec_DecodeToDic will write into `state.dic` up to `state.dicPos < dicLimit`.
    const Byte* actual_payload_ptr = reinterpret_cast<const Byte*>(in_buffer.data() + LZMA_PROPS_SIZE);
    SRes res = LzmaDec_DecodeToDic(&state, state.dicBufSize,
        actual_payload_ptr, &src_len_payload,
        LZMA_FINISH_END, &status);

    state.dic = NULL;
    free(state.probs);
    state.probs = NULL;
    //LzmaDec_FreeProbs(&state, &g_LzmaAlloc);

    if (res != SZ_OK) {
        std::cerr << "LZMA: LzmaDec_DecodeToDic failed with SRes code: " << res << std::endl;
        return false;
    }

    // std::cout << "LZMA out size: " << state.dicPos << '\n';

    // After the call, state.dicPos holds the number of bytes actually written to the dictionary.
    // src_len_payload (on output) holds the number of source bytes consumed.
    if (status == LZMA_STATUS_FINISHED_WITH_MARK || status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK) {
        if (state.dicPos != expected_out_size) {
            std::cerr << "LZMA: Decompression finished, but output size mismatch. Decoded " << state.dicPos
                << " bytes, expected " << expected_out_size << " bytes." << std::endl;
            out_buffer.clear();
            // out_buffer = new uint8_t[state.dicPos];  Adjust buffer to actual decompressed size
            return false; // Size mismatch is typically an error.
        }

        SizeT expected_input_payload_to_consume = in_buffer.size() - LZMA_PROPS_SIZE;
        // Check if the amount consumed is reasonable. It might be less if the stream is shorter than the buffer.
        if (src_len_payload < expected_input_payload_to_consume && status != LZMA_STATUS_NEEDS_MORE_INPUT) {
            // std::cout << "[LZMA INFO] Consumed " << src_len_payload << " bytes from input payload of "
            //    << expected_input_payload_to_consume << " bytes (stream likely ended early or had padding)." << std::endl;
        } else if (src_len_payload > expected_input_payload_to_consume) {
            // This should not happen as it cannot consume more than what's declared available.
            std::cerr << "[LZMA ERROR] Internal logic error: Consumed more bytes (" << src_len_payload
                << ") than available in input payload (" << expected_input_payload_to_consume << ")." << std::endl;
            out_buffer.clear();
            return false;
        }
        return true; // Successfully decompressed
    } else {
        std::cerr << "LZMA: Decompression did not finish as expected. Status: " << status
            << ". Decoded: " << state.dicPos << "/" << expected_out_size
            << ". Input consumed: " << src_len_payload << "/" << (in_buffer.size() - LZMA_PROPS_SIZE)
            << std::endl;
        out_buffer.clear();
        return false;
    }
}


// --- File Structures ---
#pragma pack(push, 1)
struct StkPakHeader {
    uint8_t raw_flags_version_byte;
    uint32_t signature;
    uint8_t padding[8];
    uint32_t xor_key;
    uint32_t num_entries;
    uint32_t entry_table_size;

    uint8_t version() const { return raw_flags_version_byte & 0x0F; }
    uint8_t flags_raw() const { return raw_flags_version_byte & 0xF0; }
};
#pragma pack(pop)

const uint32_t STK_PAK_SIGNATURE = 0x00000008;

struct StkFileEntry {
    // length before name
    std::string filename;
    uint32_t data_offset;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint32_t crc32_val;
    uint16_t flags;
};

template<typename T>
T read_value(const std::vector<uint8_t>& buffer, size_t& offset) {
    T val;
    if (offset + sizeof(T) > buffer.size()) {
        throw std::runtime_error("Read out of bounds attempting to read " + std::to_string(sizeof(T)) +
            " bytes at offset " + std::to_string(offset) +
            " from buffer of size " + std::to_string(buffer.size()));
    }
    memcpy(&val, buffer.data() + offset, sizeof(T));
    offset += sizeof(T);
    return val;
}

inline static bool uncompress_entry_file(
    const StkFileEntry& entry,
    const StkPakHeader& header,
    std::vector<uint8_t>& buffer, // decrypted and CRC checked
    std::vector<uint8_t>& result) {

    bool succes = false;
    if (entry.compressed_size < 5) {
        result.clear();
        return false;
    }

    if (entry.compressed_size == 0) {
        if (entry.uncompressed_size == 0) {
            // std::cout << "  File: " << entry.filename << " - Empty (C:0, U:0).\n";
            // uncompressed_final_data is already empty
            succes = true;
        } else {
            // Compressed 0, Uncompressed > 0. This is odd.
            // std::cout << "  File: " << entry.filename << " - Compressed size is 0, Uncompressed size is "
            //    << entry.uncompressed_size << ". Treating as uncompressed zero-filled data.\n";
            result = std::vector<uint8_t>(entry.uncompressed_size);
            succes = true; // Or false, depending on how strictly you interpret "decompression"
        }
    } else if (entry.uncompressed_size == entry.compressed_size) {
        // std::cout << "  File: " << entry.filename << " - Data appears uncompressed (C:" << entry.compressed_size
        //    << ", U:" << entry.uncompressed_size << "). Using processed data directly.\n";
        result = std::vector<uint8_t>(entry.uncompressed_size);
        memcpy(buffer.data(), result.data(), entry.uncompressed_size);
        succes = true;
    } else {
        /*if (entry.uncompressed_size < entry.compressed_size)
            std::cout << "  File: " << entry.filename << " - Suspicious sizes for decompression (C:" << entry.compressed_size
            << ", U:" << entry.uncompressed_size << ").\n";*/

        if (header.version() < 3) {
            // std::cout << "UCL Method\n";
            succes = decompress_ucl(buffer, result, entry.uncompressed_size);
        } else { // version >= 3
            uint8_t compression_method_flags = header.flags_raw() & 0x30;
            if (compression_method_flags == 0x00) {
                // std::cout << "ZLIB Method\n";
                succes = decompress_zlib(buffer, result, entry.uncompressed_size);
            } else if (compression_method_flags == 0x10) {
                // std::cout << "LZMA Method\n";
                succes = decompress_lzma(buffer, result, entry.uncompressed_size);
            } else {
                /* std::cout << "Unsupported/Unknown Compression Method (header.flags_raw & 0x30 = 0x"
                    << std::hex << (int)compression_method_flags << std::dec
                    << "). Decompression marked as FAILED.\n";*/
                succes = false;
            }
        }
    }

    // Post-decompression checks
    if (succes) {
        if (result.size() != entry.uncompressed_size) {
            std::cerr << "  File: " << entry.filename
                << " - WARNING: Decompressed size (" << result.size()
                << ") does not match expected uncompressed size (" << entry.uncompressed_size << ").\n";
            // Depending on strictness, you might set decomp_ok = false here or try to resize/truncate.
            // For safety, let's say it's an issue if sizes don't match after "successful" decompression.
            // However, if U_size was 0 and C_size was 0, final size being 0 is fine.
            if (entry.uncompressed_size > 0 || (entry.uncompressed_size == 0 && result.size() != 0)) {
                // If expected uncompressed is >0, or expected is 0 but we got something, it's a mismatch.
                std::cerr << "    This is considered a failure for a non-empty expected file.\n";
                succes = false; // Treat as failure if sizes mismatch post-op
                result.clear();
            }
        } else {
            // std::cout << "  File: " << entry.filename << " - Decompression/processing successful.\n";
        }
    } else {
        result.clear();
    }

    return succes;
}


int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input_stk_pak_file> <output_directory>" << std::endl;
        return 1;
    }

    std::string input_filepath = argv[1];
    std::filesystem::path output_dir_base = argv[2];

    std::ifstream ifs(input_filepath, std::ios::binary);
    if (!ifs) {
        std::cerr << "Error: Could not open input file: " << input_filepath << std::endl;
        return 1;
    }

    StkPakHeader header;
    ifs.read(reinterpret_cast<char*>(&header), sizeof(StkPakHeader));
    if (ifs.gcount() != sizeof(StkPakHeader)) {
        std::cerr << "Error: Could not read STK PAK header." << std::endl;
        return 1;
    }

    std::cout << "STK Header Info:\n";
    std::cout << "  Raw Byte: 0x" << std::hex << (int)header.raw_flags_version_byte << std::dec << "\n";
    std::cout << "  Version: " << (int)header.version() << "\n";
    std::cout << "  Flags Raw: 0x" << std::hex << (int)header.flags_raw() << std::dec << "\n";
    std::cout << "  Signature: 0x" << std::hex << header.signature << std::dec << "\n";
    std::cout << "  Entry Table Key: 0x" << std::hex << header.xor_key << std::dec << "\n";
    std::cout << "  Num Entries: " << header.num_entries << "\n";
    std::cout << "  Entry Table Encrypted Size: " << header.entry_table_size << std::dec << ")\n";

    if (header.signature != STK_PAK_SIGNATURE) {
        std::cerr << "Error: Invalid STK PAK signature." << std::endl;
        return 1;
    }

    if (header.entry_table_size == 0 && header.num_entries > 0) {
        std::cerr << "Error: Entry table size is 0 but num_entries is " << header.num_entries << std::endl;
        return 1;
    }

    std::vector<uint8_t> entry_table_buffer(header.entry_table_size);
    if (header.entry_table_size > 0) {
        ifs.read(reinterpret_cast<char*>(entry_table_buffer.data()), header.entry_table_size);
        if (ifs.gcount() != static_cast<std::streamsize>(header.entry_table_size)) {
            std::cerr << "Error: Could not read full entry table." << std::endl;
            return 1;
        }
        xor_crypt(entry_table_buffer, header.xor_key);
    }


    std::vector<StkFileEntry> file_entries;
    size_t current_et_offset = 0;
    for (uint32_t i = 0; i < header.num_entries; ++i) {
        try {
            StkFileEntry entry;
            uint32_t filename_len = read_value<uint32_t>(entry_table_buffer, current_et_offset);
            if (filename_len > 2048 || filename_len == 0) {
                std::cerr << "Error: Invalid filename length (" << filename_len << ") for entry " << i << std::endl;
                return 1;
            }
            if (current_et_offset + filename_len > entry_table_buffer.size()) {
                throw std::runtime_error("Filename read out of bounds for entry " + std::to_string(i));
            }
            entry.filename.assign(reinterpret_cast<const char*>(entry_table_buffer.data() + current_et_offset), filename_len);
            current_et_offset += filename_len;

            entry.data_offset = read_value<uint32_t>(entry_table_buffer, current_et_offset);
            entry.compressed_size = read_value<uint32_t>(entry_table_buffer, current_et_offset);
            entry.uncompressed_size = read_value<uint32_t>(entry_table_buffer, current_et_offset);
            entry.crc32_val = read_value<uint32_t>(entry_table_buffer, current_et_offset);
            entry.flags = read_value<uint16_t>(entry_table_buffer, current_et_offset);
            file_entries.push_back(entry);
        }
        catch (const std::runtime_error& e) {
            std::cerr << "Error parsing entry " << i << ": " << e.what() << std::endl;
            return 1;
        }
    }
    std::cout << "Parsed " << file_entries.size() << " file entries.\n";

    int cur_entry = 0;
    for (const auto& entry : file_entries) {
        if (cur_entry % 100 == 0)
            std::cout << "Processed " << cur_entry << " files\n";
        cur_entry++;

        /* std::cout << "Processing: " << entry.filename
            << " (Offset: 0x" << std::hex << entry.data_offset
            << ", CompSize: " << std::dec << entry.compressed_size
            << ", UncompSize: " << entry.uncompressed_size
            << ", CRC: " << std::hex << entry.crc32_val
            << ", Flags: 0x" << std::hex << entry.flags << std::dec << ")\n";*/

        uint64_t current_file_data_offset_in_pak = header.entry_table_size + entry.data_offset;
        ifs.seekg(current_file_data_offset_in_pak, std::ios::beg);

        std::vector<uint8_t> file_data_buffer(entry.compressed_size);
        if (entry.compressed_size > 0) {
            ifs.read(reinterpret_cast<char*>(file_data_buffer.data()), entry.compressed_size);
            if (ifs.gcount() != static_cast<std::streamsize>(entry.compressed_size)) {
                std::cerr << "  Error reading data for " << entry.filename << ". Read " << ifs.gcount() << "/" << entry.compressed_size << std::endl;
                continue;
            }
        }
        
        xor_crypt(file_data_buffer, header.xor_key);
        int computed_crc = compute_crc32(file_data_buffer);

        if (computed_crc != entry.crc32_val) {
            std::cerr << "Warning: CRC mismath! (" << std::hex << computed_crc << " != " << entry.crc32_val << ") for " << entry.filename << std::endl;
            // std::cout << std::dec;
            continue;
        }

        std::vector<uint8_t> uncompressed_data(0);
        try {
            if (!uncompress_entry_file(entry, header, file_data_buffer, uncompressed_data)) {
                std::cerr << "Warning: Failed decompress " << entry.filename << std::endl;
                continue;
            }
        }
        catch (const std::runtime_error& e) {
            std::cerr << "Error uncompressing " << entry.filename << ": " << e.what() << std::endl;
            return 1;
        }

        if (uncompressed_data.size() != 0) {
            std::filesystem::path out_file_path = output_dir_base / entry.filename;
            try {
                std::filesystem::create_directories(out_file_path.parent_path());
                std::ofstream ofs(out_file_path, std::ios::binary);
                if (!ofs) {
                    std::cerr << "  Error creating output file: " << out_file_path << std::endl;
                } else {
                    ofs.write(reinterpret_cast<const char*>(uncompressed_data.data()), uncompressed_data.size());
                    // std::cout << "  Extracted to: " << out_file_path << " (" << uncompressed_data.size() << " bytes)\n";
                }
            }
            catch (const std::exception& e) {
                std::cerr << "  Exception creating directory/file " << out_file_path << ": " << e.what() << std::endl;
            }
        } else if (entry.uncompressed_size == 0) {
            std::filesystem::path out_file_path = output_dir_base / entry.filename;
            try {
                std::filesystem::create_directories(out_file_path.parent_path());
                std::ofstream ofs_empty(out_file_path, std::ios::binary); // Create empty file
                // std::cout << "  Created empty file after processing: " << out_file_path << std::endl;
            }
            catch (const std::exception& e) {
                std::cerr << "  Error creating directory/empty file " << out_file_path << ": " << e.what() << std::endl;
            }
        } else {
            // std::cout << "  No data to write for " << entry.filename << " (decompression might have failed or was empty).\n";
        }
    }

    std::cout << "Extraction process finished." << std::endl;
    return 0;
}