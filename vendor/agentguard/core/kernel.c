#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(_MSC_VER)
  #include <intrin.h>
  #define popcount64(x) __popcnt64(x)
#else
  #define popcount64(x) __builtin_popcountll(x)
#endif

#if defined(_WIN32)
  #define EXPORT_API __declspec(dllexport)
#else
  #define EXPORT_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Full 64-bit friction evaluation between agent status mask and payload hash.
 * Returns the exact popcount of XOR differences (0..64).
 */
EXPORT_API uint64_t evaluate_agent_friction(uint64_t agent_status_mask, uint64_t payload_hash) {
    uint64_t diff = agent_status_mask ^ payload_hash;
    return (uint64_t)popcount64(diff);
}

/**
 * High-speed SWAR bit-level noise & transition analyzer over a byte buffer.
 * Utilizes alignment-safe 64-bit memcpy operations without conditional branches.
 */
EXPORT_API double analyze_swar_buffer(const char* data, size_t len) {
    if (!data || len == 0) return 0.0;

    uint64_t noise_accum = 0;
    size_t full_blocks = len / 8;
    size_t tail_bytes  = len % 8;

    for (size_t i = 0; i < full_blocks; i++) {
        uint64_t block = 0;
        memcpy(&block, data + (i * 8), 8);
        uint64_t high_bits       = block & 0x8080808080808080ULL;
        uint64_t bit_transitions = (block ^ (block >> 1)) & 0x5555555555555555ULL;

        noise_accum += (uint64_t)popcount64(high_bits)
                     + (uint64_t)popcount64(bit_transitions);
    }

    if (tail_bytes > 0) {
        uint64_t block = 0;
        memcpy(&block, data + (full_blocks * 8), tail_bytes);
        uint64_t high_bits       = block & 0x8080808080808080ULL;
        uint64_t bit_transitions = (block ^ (block >> 1)) & 0x5555555555555555ULL;

        noise_accum += (uint64_t)popcount64(high_bits)
                     + (uint64_t)popcount64(bit_transitions);
    }

    size_t total_inspected_bits = (full_blocks * 32) + (tail_bytes * 4);
    if (total_inspected_bits == 0) return 0.0;

    double base_score = (double)noise_accum / (double)total_inspected_bits;
    return (base_score > 1.0) ? 1.0 : base_score;
}

/**
 * SWAR hasZero byte-matching vector operation.
 * Scans 64-bit word for target byte matching without branching (test_aom-1 fix).
 * Returns mask with 0x80 on byte positions where target_byte matches.
 */
EXPORT_API uint64_t swar_match_byte_64(uint64_t word, uint8_t target_byte) {
    const uint64_t M01 = 0x0101010101010101ULL;
    const uint64_t mask_ctrl = 0x8080808080808080ULL;

    uint64_t target_word = M01 * target_byte;
    uint64_t xorw = word ^ target_word;
    /* Standard branchless hasZero pattern */
    return (xorw - M01) & ~xorw & mask_ctrl;
}

/**
 * Ultra-fast SpMM core for dense/sparse matrix transformations aligned to bit-blocks.
 */
EXPORT_API void spmm_hbag_dense_mult(const float* A, const float* B, float* C, int M, int N, int K) {
    for (int i = 0; i < M; i++) {
        const float* a_row = &A[i * K];
        float* c_row = &C[i * N];
        for (int j = 0; j < N; j++) {
            float sum = 0.0f;
            for (int k = 0; k < K; k++) {
                sum += a_row[k] * B[k * N + j];
            }
            c_row[j] = sum;
        }
    }
}

#ifdef __cplusplus
}
#endif
