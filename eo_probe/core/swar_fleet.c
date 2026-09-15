#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(_WIN32)
  #define EXPORT_API __declspec(dllexport)
#else
  #define EXPORT_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Branchless 64-bit friction between agent status mask and payload hash.
 * Returns popcount of differing bits under the 0x55.. pattern (max 32).
 */
EXPORT_API uint64_t evaluate_agent_friction(uint64_t agent_status_mask, uint64_t payload_hash) {
    uint64_t pattern = 0x5555555555555555ULL;
    uint64_t friction_bits = (agent_status_mask ^ payload_hash) & pattern;
    return (uint64_t)__builtin_popcountll(friction_bits);
}

/**
 * Highly optimized SWAR text bit-level noise / entropy score over a raw buffer.
 * Processes 64-bit uint64_t words branchlessly for maximum CPU vector/SWAR throughput.
 */
EXPORT_API double analyze_swar_buffer(const char* data, size_t len) {
    if (!data || len == 0) return 0.0;

    uint64_t noise_accum = 0;
    size_t full_blocks = len / 8;
    size_t tail_bytes  = len % 8;

    const uint64_t* ptr64 = (const uint64_t*)data;
    for (size_t i = 0; i < full_blocks; i++) {
        uint64_t block = ptr64[i];
        uint64_t high_bits       = block & 0x8080808080808080ULL;
        uint64_t bit_transitions = (block ^ (block >> 1)) & 0x5555555555555555ULL;

        noise_accum += (uint64_t)__builtin_popcountll(high_bits)
                     + (uint64_t)__builtin_popcountll(bit_transitions);
    }

    if (tail_bytes > 0) {
        uint64_t block = 0;
        memcpy(&block, data + (full_blocks * 8), tail_bytes);
        uint64_t high_bits       = block & 0x8080808080808080ULL;
        uint64_t bit_transitions = (block ^ (block >> 1)) & 0x5555555555555555ULL;

        noise_accum += (uint64_t)__builtin_popcountll(high_bits)
                     + (uint64_t)__builtin_popcountll(bit_transitions);
    }

    size_t total_inspected_bits = (full_blocks * 32) + (tail_bytes * 4);
    if (total_inspected_bits == 0) return 0.0;

    double base_score = (double)noise_accum / (double)total_inspected_bits;
    return (base_score > 1.0) ? 1.0 : base_score;
}

#ifdef __cplusplus
}
#endif
