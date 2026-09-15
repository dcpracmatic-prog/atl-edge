#include "friction_core.hpp"
#include <cstdio>
#include <cstring>

int main() {
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(i * 7 + 3);

    smart_token::SequentialTarpit tarpit(key, "cpu", 0.8);

    std::printf("=== C++ Sequential Tarpit Demo ===\n");
    for (int i = 1; i <= 3; ++i) {
        tarpit.register_failure();
        const auto& s = tarpit.state();
        std::printf("Fail %d -> count=%d fib=%d persist=%d tarpit=%d\n",
                    i, s.fail_count, s.flag_fibonacci, s.flag_persistencia, s.tarpit_triggered);
    }

    uint8_t material[32], salt[16];
    for (int i = 0; i < 32; ++i) material[i] = (uint8_t)i;
    for (int i = 0; i < 16; ++i) salt[i] = (uint8_t)(i + 50);
    double H = smart_token::coherence_metric(material, 32, salt, 16);
    std::printf("Coherence metric sample: %.6f\n", H);

    tarpit.reset();
    std::printf("After reset: fail_count=%d\n", tarpit.state().fail_count);
    std::printf("C++ core OK\n");
    return 0;
}
