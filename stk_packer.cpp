// Actually doesn't work, engine can't decompress entries somewhy
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
#include <stdexcept>
#include <array>
#include <thread>
#include <mutex>
#include <atomic>

// LZMA SDK headers
extern "C" {
#include "c/LzmaEnc.h"
#include "c/LzmaLib.h"
}

// CRC32 calculation
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

    return ~crc; // Standard CRC-32 final XOR
}

// XOR encryption/decryption
inline static void xor_crypt(std::vector<uint8_t>& buffer, uint32_t key) {
    if (buffer.empty()) return;
    uint8_t key_bytes[4];
    memcpy(key_bytes, &key, 4);
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] ^= key_bytes[i & 3]; // i % 4
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
};
#pragma pack(pop)

const uint32_t STK_PAK_SIGNATURE = 0x00000008;

struct StkFileEntryInfo {
    std::string filename;
    uint32_t data_offset;
    uint32_t compressed_size_in_stk;
    uint32_t uncompressed_size;
    uint32_t crc32;
    uint16_t flags;
    std::vector<uint8_t> temp_compressed_data;
};

template<typename T>
inline static void append_value_le(std::vector<uint8_t>& buffer, T value) {
    const uint8_t* val_ptr = reinterpret_cast<const uint8_t*>(&value);
    buffer.insert(buffer.end(), val_ptr, val_ptr + sizeof(T));
}

inline static void append_string_raw(std::vector<uint8_t>& buffer, const std::string& str) {
    buffer.insert(buffer.end(), str.begin(), str.end());
}

// LZMA Compression Function
inline static bool compress_data_lzma(const std::vector<uint8_t>& uncompressed_data,
    std::vector<uint8_t>& compressed_data_with_props) {
    compressed_data_with_props.clear();
    if (uncompressed_data.empty()) {
        return true;
    }

    CLzmaEncProps props;
    LzmaEncProps_Init(&props);
    props.level = 9;
    props.dictSize = 1 << 24; // 16MB dictionary
    props.numThreads = 1;     // IMPORTANT: We parallelize files, not a single compression op.

    std::vector<Byte> lzma_props_buffer(LZMA_PROPS_SIZE);
    SizeT lzma_props_size_actual = LZMA_PROPS_SIZE;

    // Pre-allocate a generous buffer for the compressed data
    SizeT compressed_data_only_len = uncompressed_data.size() * 1.1 + 256;
    if (compressed_data_only_len < 256) compressed_data_only_len = 256;

    std::vector<Byte> compressed_data_only_buffer(compressed_data_only_len);

    SRes lzma_res = LzmaCompress(
        compressed_data_only_buffer.data(), &compressed_data_only_len,
        uncompressed_data.data(), uncompressed_data.size(),
        lzma_props_buffer.data(), &lzma_props_size_actual,
        props.level, props.dictSize, props.lc, props.lp, props.pb, props.fb, props.numThreads
    );

    if (lzma_res == SZ_OK) {
        if (lzma_props_size_actual != LZMA_PROPS_SIZE) {
            std::cerr << "LZMA Compress: Props size mismatch. Expected " << LZMA_PROPS_SIZE << ", got " << lzma_props_size_actual << std::endl;
            return false;
        }
        compressed_data_with_props.resize(LZMA_PROPS_SIZE + compressed_data_only_len);
        memcpy(compressed_data_with_props.data(), lzma_props_buffer.data(), LZMA_PROPS_SIZE);
        memcpy(compressed_data_with_props.data() + LZMA_PROPS_SIZE, compressed_data_only_buffer.data(), compressed_data_only_len);
        return true;
    } else {
        std::cerr << "LZMA Compression failed for a file of size " << uncompressed_data.size()
            << " with SRes code: " << lzma_res << std::endl;
        if (lzma_res == SZ_ERROR_OUTPUT_EOF) {
            std::cerr << "  (SZ_ERROR_OUTPUT_EOF: Insufficient buffer for compressed data. Tried buffer size: "
                << compressed_data_only_buffer.size() << ")" << std::endl;
        }
        return false;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input_directory> <output_stk_file>" << std::endl;
        std::cerr << "  Example: " << argv[0] << " ./my_assets_dir package.stk" << std::endl;
        return 1;
    }

    std::filesystem::path input_dir_path(argv[1]);
    std::filesystem::path output_stk_filepath(argv[2]);

    if (!std::filesystem::is_directory(input_dir_path)) {
        std::cerr << "Error: Input path is not a directory: " << input_dir_path << std::endl;
        return 1;
    }
    input_dir_path = std::filesystem::absolute(input_dir_path).lexically_normal();

    // --- Phase 1: Collect file paths (serially) ---
    std::vector<std::filesystem::path> file_paths;
    std::cout << "Scanning directory for files: " << input_dir_path << std::endl;
    try {
        for (const auto& dir_entry : std::filesystem::recursive_directory_iterator(input_dir_path)) {
            if (dir_entry.is_regular_file()) {
                file_paths.push_back(dir_entry.path());
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Filesystem error during scan: " << e.what() << std::endl;
        return 1;
    }
    std::cout << "Found " << file_paths.size() << " files to process." << std::endl;

    // --- Phase 2: Read and compress files in parallel ---
    const unsigned int num_threads = std::thread::hardware_concurrency();
    std::cout << "Using " << num_threads << " threads for compression." << std::endl;

    std::vector<StkFileEntryInfo> all_entries_info;
    std::mutex results_mutex;
    std::atomic<size_t> next_file_index = 0;
    std::atomic<int> progress_counter = 0;
    std::mutex cout_mutex;

    auto worker_function = [&]() {
        while (true) {
            size_t file_index = next_file_index.fetch_add(1);
            if (file_index >= file_paths.size()) {
                break; // No more files to process
            }

            const auto& full_path = file_paths[file_index];
            std::filesystem::path relative_path_fs = std::filesystem::relative(full_path, input_dir_path);
            std::string relative_path_str = relative_path_fs.generic_string();

            StkFileEntryInfo entry;
            entry.filename = relative_path_str;

            std::ifstream file_reader(full_path, std::ios::binary | std::ios::ate);
            if (!file_reader) {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cerr << "  Warning: Could not open file: " << full_path << ". Skipping." << std::endl;
                continue;
            }
            std::streamsize size = file_reader.tellg();
            file_reader.seekg(0, std::ios::beg);

            std::vector<uint8_t> original_content(size);
            entry.uncompressed_size = static_cast<uint32_t>(size);

            if (size > 0) {
                if (!file_reader.read(reinterpret_cast<char*>(original_content.data()), size)) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cerr << "  Warning: Could not read file: " << full_path << ". Skipping." << std::endl;
                    continue;
                }
            }
            file_reader.close();

            if (!compress_data_lzma(original_content, entry.temp_compressed_data)) {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cerr << "  Error: LZMA compression failed for " << relative_path_str << ". Skipping." << std::endl;
                continue;
            }

            entry.compressed_size_in_stk = static_cast<uint32_t>(entry.temp_compressed_data.size());

            {
                std::lock_guard<std::mutex> lock(results_mutex);
                all_entries_info.push_back(std::move(entry));
            }

            int processed_count = progress_counter.fetch_add(1) + 1;
            if (processed_count % 100 == 0 || processed_count == file_paths.size()) {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << "Compressed " << processed_count << " / " << file_paths.size() << " files..." << std::endl;
            }
        }
    };

    std::vector<std::thread> workers;
    for (unsigned int i = 0; i < num_threads; ++i) {
        workers.emplace_back(worker_function);
    }

    for (auto& worker : workers) {
        worker.join();
    }

    std::cout << "Compression complete. Collected " << all_entries_info.size() << " entries." << std::endl;

    // --- Phase 3: Categorize and order entries ---
    std::vector<StkFileEntryInfo> resources_entries_info;
    std::vector<StkFileEntryInfo> other_entries_info;
    for (auto& entry : all_entries_info) {
        if (entry.filename.rfind("Resources/", 0) == 0) {
            resources_entries_info.push_back(std::move(entry));
        } else {
            other_entries_info.push_back(std::move(entry));
        }
    }

    std::vector<StkFileEntryInfo> final_ordered_entries_info;
    final_ordered_entries_info.reserve(resources_entries_info.size() + other_entries_info.size());
    final_ordered_entries_info.insert(final_ordered_entries_info.end(),
        std::make_move_iterator(resources_entries_info.begin()),
        std::make_move_iterator(resources_entries_info.end()));
    final_ordered_entries_info.insert(final_ordered_entries_info.end(),
        std::make_move_iterator(other_entries_info.begin()),
        std::make_move_iterator(other_entries_info.end()));

    // --- Phase 4: Calculate offsets, CRCs, and build data blocks ---
    std::vector<std::vector<uint8_t>> all_xored_file_data_blocks;
    all_xored_file_data_blocks.reserve(final_ordered_entries_info.size());
    uint32_t current_data_offset_accumulator = 0;

    for (auto& entry_info : final_ordered_entries_info) {
        entry_info.data_offset = current_data_offset_accumulator;
        entry_info.flags = 0x0004; // Default flag
        entry_info.crc32 = compute_crc32(entry_info.temp_compressed_data);
        current_data_offset_accumulator += entry_info.compressed_size_in_stk;
    }

    // --- Phase 5: Construct Entry Table ---
    std::vector<uint8_t> entry_table_raw_buffer;
    for (const auto& entry_info : final_ordered_entries_info) {
        if (entry_info.filename.length() > 2048) {
            std::cerr << "Warning: Filename too long: " << entry_info.filename << std::endl;
        }
        append_value_le<uint32_t>(entry_table_raw_buffer, static_cast<uint32_t>(entry_info.filename.length()));
        append_string_raw(entry_table_raw_buffer, entry_info.filename);
        append_value_le<uint32_t>(entry_table_raw_buffer, entry_info.data_offset);
        append_value_le<uint32_t>(entry_table_raw_buffer, entry_info.compressed_size_in_stk);
        append_value_le<uint32_t>(entry_table_raw_buffer, entry_info.uncompressed_size);
        append_value_le<uint32_t>(entry_table_raw_buffer, entry_info.crc32);
        append_value_le<uint16_t>(entry_table_raw_buffer, entry_info.flags);
    }

    // --- Phase 6: XOR Encryption ---
    uint32_t xor_key = compute_crc32(entry_table_raw_buffer);
    uint32_t final_entry_table_size = static_cast<uint32_t>(entry_table_raw_buffer.size());

    std::vector<uint8_t> entry_table_xored_buffer = entry_table_raw_buffer;
    if (final_entry_table_size > 0) {
        xor_crypt(entry_table_xored_buffer, xor_key);
    }

    // Now XOR the actual file data and move it to its final destination
    for (auto& entry_info : final_ordered_entries_info) {
        xor_crypt(entry_info.temp_compressed_data, xor_key);
        all_xored_file_data_blocks.push_back(std::move(entry_info.temp_compressed_data));
    }

    // --- Phase 7: Construct Header ---
    StkPakHeader header;
    header.raw_flags_version_byte = (0x10) | (0x06); // LZMA | Version 6
    header.signature = STK_PAK_SIGNATURE;
    memset(header.padding, 0x20, sizeof(header.padding));
    header.xor_key = xor_key;
    header.num_entries = static_cast<uint32_t>(final_ordered_entries_info.size());
    header.entry_table_size = final_entry_table_size + sizeof(StkPakHeader);

    // --- Phase 8: Write to output .stk file ---
    std::cout << "Writing final STK file: " << output_stk_filepath << std::endl;
    std::ofstream ofs(output_stk_filepath, std::ios::binary);
    if (!ofs) {
        std::cerr << "Error: Could not open output file for writing: " << output_stk_filepath << std::endl;
        return 1;
    }

    ofs.write(reinterpret_cast<const char*>(&header), sizeof(StkPakHeader));
    if (final_entry_table_size > 0) {
        ofs.write(reinterpret_cast<const char*>(entry_table_xored_buffer.data()), entry_table_xored_buffer.size());
    }

    for (const auto& data_block : all_xored_file_data_blocks) {
        if (!data_block.empty()) {
            ofs.write(reinterpret_cast<const char*>(data_block.data()), data_block.size());
        }
    }

    ofs.close();
    std::cout << "Successfully created STK file: " << output_stk_filepath << std::endl;
    std::cout << "  Version: " << (int)(header.raw_flags_version_byte & 0x0F)
        << ", Flags: 0x" << std::hex << (int)(header.raw_flags_version_byte & 0xF0) << std::dec << std::endl;
    std::cout << "  XOR Key: 0x" << std::hex << header.xor_key << std::dec << std::endl;
    std::cout << "  Entries: " << header.num_entries << std::endl;
    std::cout << "  Entry Table Size (raw): " << header.entry_table_size << " bytes" << std::endl;
    uint64_t total_data_size = 0;
    for (const auto& block : all_xored_file_data_blocks) total_data_size += block.size();
    std::cout << "  Total File Data Size (xored, compressed): " << total_data_size << " bytes" << std::endl;

    return 0;

}
