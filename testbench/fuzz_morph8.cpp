// Harness de fuzzing libFuzzer para el parser y predigest C++ de MORPH-8
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>

extern "C" {
typedef struct {
    int decision;          /* 0=REJECT, 1=ACCEPT, 2=REPAIR */
    double health;         /* structural score [0,1], not probability */
    double energy;         /* 1-health */
    uint32_t violations;   /* hard structural/policy-context violations */
    uint32_t state_mask;   /* 8 deterministic structural projections */
    uint32_t structural_mask; /* 1=dimension satisfied */
    uint32_t repairs;      /* semantically neutral formatting repairs */
} MorphDecision;

int morph_predigest(const char* input, std::size_t input_len,
                    const char* policy, std::size_t policy_len,
                    char* repaired, std::size_t repaired_cap,
                    MorphDecision* out);
}

static const char DEFAULT_POLICY[] =
    "allow_tool=lookup\n"
    "allow_tool=normalize\n"
    "allow_tool=validate\n"
    "allow_tool=publish\n"
    "allow_operation=read\n"
    "allow_operation=normalize\n"
    "allow_operation=validate\n"
    "allow_operation=publish\n"
    "deny_action=delete\n"
    "deny_action=drop\n"
    "deny_action=truncate\n"
    "require=tool\n"
    "require=operation\n"
    "deny_field=shell\n"
    "deny_field=exec\n"
    "deny_field=command\n";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    char repaired_buf[8192];
    MorphDecision decision;

    // Direct fuzz of predigest with default policy
    morph_predigest(
        reinterpret_cast<const char*>(data),
        size,
        DEFAULT_POLICY,
        sizeof(DEFAULT_POLICY) - 1,
        repaired_buf,
        sizeof(repaired_buf),
        &decision
    );

    // If payload contains delimiter '\0', test split fuzzing for (policy, input)
    const uint8_t* sep = static_cast<const uint8_t*>(memchr(data, '\0', size));
    if (sep) {
        size_t policy_len = sep - data;
        const char* custom_policy = reinterpret_cast<const char*>(data);
        const char* custom_input = reinterpret_cast<const char*>(sep + 1);
        size_t input_len = size - policy_len - 1;

        morph_predigest(
            custom_input,
            input_len,
            custom_policy,
            policy_len,
            repaired_buf,
            sizeof(repaired_buf),
            &decision
        );
    }

    return 0;
}
