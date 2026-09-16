#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <stdexcept>

namespace smart_token {

struct FrictionState {
    int fail_count = 0;
    bool flag_fibonacci = false;
    bool flag_persistencia = false;
    int fib_seed = 0;
    bool tarpit_triggered = false;
    uint8_t working_key[32] = {0};
};

class SequentialTarpit {
public:
    SequentialTarpit(const uint8_t* base_key_32, const char* mode = "cpu", double tarpit_seconds = 1.5);
    void register_failure();
    void reset();
    const FrictionState& state() const { return state_; }
    void current_key(uint8_t out[32]) const;

private:
    uint8_t base_key_[32];
    std::string mode_;
    double tarpit_seconds_;
    FrictionState state_;

    static uint64_t fib(int n);
    void mutate_key(const uint8_t* key, int n, uint8_t out[32]);
    void cpu_tarpit();
};

// Coherence metric (same logic as Python, using SHA-256)
// Requires a SHA-256 implementation (we use a minimal embedded one or OpenSSL if available)
double coherence_metric(const uint8_t* material, size_t mat_len,
                        const uint8_t* salt, size_t salt_len);

} // namespace smart_token

// ---------------------------------------------------------------------------
// Flat C ABI for FFI (ctypes / cffi / any language with a C interface).
// This is what smart_token_prod.native binds to via ctypes.
// ---------------------------------------------------------------------------
extern "C" {

// Opaque handle to a smart_token::SequentialTarpit instance.
typedef void* st_tarpit_handle;

// Creates a tarpit instance. base_key_32 must point to exactly 32 bytes.
// mode: "cpu" | "mutate" | anything else -> "blocked" behavior on 3rd failure.
// Returns NULL on allocation failure. Caller must call st_tarpit_destroy.
st_tarpit_handle st_tarpit_create(const uint8_t* base_key_32, const char* mode, double tarpit_seconds);

// Destroys a tarpit instance created by st_tarpit_create.
void st_tarpit_destroy(st_tarpit_handle handle);

// Registers one authentication failure and advances the friction state
// machine (warning -> key mutation -> tarpit/mutate/blocked).
void st_tarpit_register_failure(st_tarpit_handle handle);

// Resets the friction state back to fail_count == 0.
void st_tarpit_reset(st_tarpit_handle handle);

// Flat snapshot of the current friction state, safe to copy across the
// ABI boundary (no STL types).
struct StFrictionSnapshot {
    int32_t fail_count;
    int32_t flag_fibonacci;     // 0/1
    int32_t flag_persistencia;  // 0/1
    int32_t fib_seed;
    int32_t tarpit_triggered;   // 0/1
    uint8_t working_key[32];
};

// Fills out with the current friction state, including the mutated
// working key material.
void st_tarpit_snapshot(st_tarpit_handle handle, StFrictionSnapshot* out);

// Stateless coherence metric — same algorithm as the Python implementation.
double st_coherence_metric(const uint8_t* material, size_t mat_len,
                            const uint8_t* salt, size_t salt_len);

} // extern "C"
