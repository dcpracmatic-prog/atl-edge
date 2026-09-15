#include "friction_core.hpp"
#include <cmath>
#include <algorithm>

// Minimal SHA-256 (public domain style) for self-contained build
namespace {

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for (i=0,j=0; i<16; ++i,j+=4)
        m[i] = (data[j]<<24) | (data[j+1]<<16) | (data[j+2]<<8) | (data[j+3]);
    for (; i<64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i=0; i<64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85; ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c; ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i=0; i<len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i=0; i<4; ++i) {
        hash[i]    = (ctx->state[0] >> (24-i*8)) & 0xff;
        hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0xff;
        hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0xff;
        hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0xff;
        hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0xff;
        hash[i+20] = (ctx->state[5] >> (24-i*8)) & 0xff;
        hash[i+24] = (ctx->state[6] >> (24-i*8)) & 0xff;
        hash[i+28] = (ctx->state[7] >> (24-i*8)) & 0xff;
    }
}

static void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

} // anon

namespace smart_token {

uint64_t SequentialTarpit::fib(int n) {
    if (n <= 1) return n;
    uint64_t a = 0, b = 1;
    for (int i = 2; i <= n; ++i) {
        uint64_t t = a + b;
        a = b; b = t;
    }
    return b;
}

void SequentialTarpit::mutate_key(const uint8_t* key, int n, uint8_t out[32]) {
    uint8_t buf[32 + 16 + 9];
    memcpy(buf, key, 32);
    // 16-byte big-endian encoding of fib(n). High 8 bytes are zero because
    // fib is uint64_t; only shift within [0, 56] to stay defined under UBSan.
    uint64_t f = fib(n);
    for (int i = 0; i < 8; ++i)
        buf[32 + i] = 0;
    for (int i = 0; i < 8; ++i)
        buf[32 + 8 + i] = static_cast<uint8_t>((f >> (8 * (7 - i))) & 0xffu);
    memcpy(buf + 48, "|FRICTION", 9);
    sha256(buf, 32 + 16 + 9, out);
}

void SequentialTarpit::cpu_tarpit() {
    auto start = std::chrono::steady_clock::now();
    int n = 2;
    while (true) {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - start).count();
        if (elapsed >= tarpit_seconds_) break;
        (void)fib(n);
        n = (n % 40) + 2;
    }
}

SequentialTarpit::SequentialTarpit(const uint8_t* base_key_32, const char* mode, double tarpit_seconds)
    : mode_(mode), tarpit_seconds_(tarpit_seconds) {
    memcpy(base_key_, base_key_32, 32);
    memcpy(state_.working_key, base_key_32, 32);
}

void SequentialTarpit::register_failure() {
    state_.fail_count++;
    if (state_.fail_count == 1) {
        state_.flag_fibonacci = true;
        state_.fib_seed = 20 + (((base_key_[0] << 8) | base_key_[1]) % 10);
    } else if (state_.fail_count == 2) {
        state_.flag_persistencia = true;
        int n = state_.fib_seed + 5;
        mutate_key(base_key_, n, state_.working_key);
    } else {
        state_.tarpit_triggered = true;
        if (mode_ == "cpu") {
            cpu_tarpit();
        } else if (mode_ == "mutate") {
            int n = state_.fib_seed + 30;
            mutate_key(base_key_, n, state_.working_key);
        }
    }
}

void SequentialTarpit::reset() {
    state_ = FrictionState();
    memcpy(state_.working_key, base_key_, 32);
}

void SequentialTarpit::current_key(uint8_t out[32]) const {
    memcpy(out, state_.working_key, 32);
}

double coherence_metric(const uint8_t* material, size_t mat_len,
                        const uint8_t* salt, size_t salt_len) {
    // material + "|C1|" + salt
    std::vector<uint8_t> buf1(mat_len + 4 + salt_len);
    memcpy(buf1.data(), material, mat_len);
    memcpy(buf1.data() + mat_len, "|C1|", 4);
    memcpy(buf1.data() + mat_len + 4, salt, salt_len);
    uint8_t h1[32];
    sha256(buf1.data(), buf1.size(), h1);

    std::vector<uint8_t> buf2(salt_len + 4 + mat_len);
    memcpy(buf2.data(), salt, salt_len);
    memcpy(buf2.data() + salt_len, "|C2|", 4);
    memcpy(buf2.data() + salt_len + 4, material, mat_len);
    uint8_t h2[32];
    sha256(buf2.data(), buf2.size(), h2);

    uint64_t v1 = 0, v2 = 0;
    for (int i = 0; i < 8; ++i) {
        v1 = (v1 << 8) | h1[i];
        v2 = (v2 << 8) | h2[i];
    }
    double f1 = v1 / (double)(uint64_t(-1));
    double f2 = v2 / (double)(uint64_t(-1));
    double c = 1.0 - std::fabs(f1 - f2);
    double b = (f1 + f2) / 2.0;
    double score = 0.55 * c + 0.45 * b;
    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    return score;
}

} // namespace smart_token

// ---------------------------------------------------------------------------
// Flat C ABI implementation
// ---------------------------------------------------------------------------
extern "C" {

st_tarpit_handle st_tarpit_create(const uint8_t* base_key_32, const char* mode, double tarpit_seconds) {
    try {
        return new smart_token::SequentialTarpit(base_key_32, mode ? mode : "cpu", tarpit_seconds);
    } catch (...) {
        return nullptr;
    }
}

void st_tarpit_destroy(st_tarpit_handle handle) {
    delete static_cast<smart_token::SequentialTarpit*>(handle);
}

void st_tarpit_register_failure(st_tarpit_handle handle) {
    if (!handle) return;
    static_cast<smart_token::SequentialTarpit*>(handle)->register_failure();
}

void st_tarpit_reset(st_tarpit_handle handle) {
    if (!handle) return;
    static_cast<smart_token::SequentialTarpit*>(handle)->reset();
}

void st_tarpit_snapshot(st_tarpit_handle handle, StFrictionSnapshot* out) {
    if (!handle || !out) return;
    auto* t = static_cast<smart_token::SequentialTarpit*>(handle);
    const auto& s = t->state();
    out->fail_count = s.fail_count;
    out->flag_fibonacci = s.flag_fibonacci ? 1 : 0;
    out->flag_persistencia = s.flag_persistencia ? 1 : 0;
    out->fib_seed = s.fib_seed;
    out->tarpit_triggered = s.tarpit_triggered ? 1 : 0;
    t->current_key(out->working_key);
}

double st_coherence_metric(const uint8_t* material, size_t mat_len,
                            const uint8_t* salt, size_t salt_len) {
    return smart_token::coherence_metric(material, mat_len, salt, salt_len);
}

} // extern "C"
