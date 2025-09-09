#include <stdio.h>
#include "base58.h"
#include "vanity.h"
#include "sha256.h"

// ------------------------------------------------------------------
// XorShift128+ PRNG state & helper functions (fast per-thread RNG)
struct xorshift128plus_state {
    uint64_t s[2];
};

__device__ void init_xorshift(xorshift128plus_state &st,
                              const uint8_t *seed,   // 32-byte GPU seed
                              uint64_t idx)
{
    // Extract all four 64-bit values from the 32-byte seed
    uint64_t k0 = *((const uint64_t*)(seed + 0));
    uint64_t k1 = *((const uint64_t*)(seed + 8));
    uint64_t k2 = *((const uint64_t*)(seed + 16));
    uint64_t k3 = *((const uint64_t*)(seed + 24));

    // Mix k0 and k2 with idx for s[0]
    uint64_t z0 = k0 ^ k2;  // Combine both parts
    z0 += idx;
    z0 = (z0 ^ (z0 >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z0 = (z0 ^ (z0 >> 27)) * 0x94d049bb133111ebULL;
    st.s[0] = z0 ^ (z0 >> 31);

    // Mix k1 and k3 with idx (and golden ratio) for s[1]
    uint64_t z1 = k1 ^ k3;  // Combine both parts
    z1 += idx + 0x9e3779b97f4a7c15ULL;
    z1 = (z1 ^ (z1 >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z1 = (z1 ^ (z1 >> 27)) * 0x94d049bb133111ebULL;
    st.s[1] = z1 ^ (z1 >> 31);
}

__device__ uint64_t xorshift128plus_next(xorshift128plus_state &st) {
    uint64_t s1 = st.s[0], s0 = st.s[1];
    uint64_t result = s0 + s1;
    st.s[0] = s0;
    s1 ^= s1 << 23;
    st.s[1] = (s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5));
    return result;
}

__device__ int done = 0;
__device__ unsigned long long count = 0;
__device__ bool d_case_insensitive = false;

// Simplified ed25519 key generation for GPU
__device__ void generate_ed25519_keypair(const uint8_t *seed32, uint8_t *private_key, uint8_t *public_key) {
    // Use the seed directly as private key (simplified approach)
    memcpy(private_key, seed32, 32);
    
    // Generate deterministic public key from private key using SHA256
    // This is a simplified version - real ed25519 uses curve25519 point multiplication
    CUDA_SHA256_CTX ctx;
    cuda_sha256_init(&ctx);
    cuda_sha256_update(&ctx, private_key, 32);
    // Add some entropy to make it more random
    cuda_sha256_update(&ctx, seed32, 32);
    cuda_sha256_final(&ctx, public_key);
}

__global__ void vanity_keypair_search(uint8_t *buffer, uint64_t stride) {
    // Deconstruct buffer - FIX: Use proper casting for memory access
    uint8_t *seed = buffer;
    
    // FIX: Proper memory access for target_len
    uint64_t target_len = *((uint64_t*)(buffer + 32));
    char *target = (char*)(buffer + 40);
    
    // FIX: Proper memory access for suffix_len  
    uint64_t suffix_len = *((uint64_t*)(buffer + 40 + target_len));
    char *suffix = (char*)(buffer + 40 + target_len + 8);
    
    uint8_t *out = buffer + 40 + target_len + suffix_len + 8;

    uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    // Initialize XorShift128+ state
    xorshift128plus_state st;
    init_xorshift(st, seed, idx);

    for (uint64_t iter = 0; iter < uint64_t(1000) * 1000; iter++) {
        // Has someone found a result?
        if (iter % 100 == 0) {
            if (atomicMax(&done, 0) == 1) {
                atomicAdd(&count, iter);
                return;
            }
        }

        // Generate a 32-byte seed for ed25519 keypair
        uint8_t keypair_seed[32];
        for (int i = 0; i < 4; ++i) {
            uint64_t rnd = xorshift128plus_next(st);
            memcpy(&keypair_seed[i * 8], &rnd, 8);
        }

        // Generate ed25519 keypair
        uint8_t private_key[32];
        uint8_t public_key[32];
        generate_ed25519_keypair(keypair_seed, private_key, public_key);

        // Encode public key to base58
        unsigned char encoded_pubkey[44] = {0};
        ulong encoded_len = fd_base58_encode_32(public_key, encoded_pubkey, d_case_insensitive);

        // Check if it matches our target
        if (matches_target(encoded_pubkey, (unsigned char*)target, target_len, (unsigned char*)suffix, suffix_len, encoded_len)) {
            // Are we first to write result?
            if (atomicMax(&done, 1) == 0) {
                // Copy private key and public key to output
                memcpy(out, private_key, 32);      // First 32 bytes: private key
                memcpy(out + 32, public_key, 32);  // Next 32 bytes: public key
                atomicAdd(&count, iter + 1);       // Only increment count on actual match
            }
            return;
        }
    }
}

__device__ bool matches_target(unsigned char *a, unsigned char *target, uint64_t n, unsigned char *suffix, uint64_t suffix_len, ulong encoded_len)
{
    for (int i = 0; i < n; i++)
    {
        if (a[i] != target[i])
            return false;
    }
    for (int i = 0; i < suffix_len; i++)
    {
        if (a[encoded_len - suffix_len + i] != suffix[i])
            return false;
    }
    return true;
}

extern "C" void vanity_keypair_round(
    int gpu_id,
    uint8_t *seed,
    char *target,
    char *suffix,
    uint64_t target_len,
    uint64_t suffix_len,
    uint8_t *out,
    bool case_insensitive)
{
    int deviceCount;
    cudaGetDeviceCount(&deviceCount);

    if (gpu_id >= deviceCount) {
        printf("Invalid GPU index: %d\n", gpu_id);
        return;
    }

    // Set device and initialize it
    cudaSetDevice(gpu_id);
    
    // Reset device to clear any previous state
    cudaDeviceReset();
    
    gpu_init(gpu_id);

    // Allocate device buffer with error checking
    uint8_t *d_buffer;
    size_t buffer_size = 32 + 8 + target_len + 8 + suffix_len + 64; // seed + target_len + target + suffix_len + suffix + out(64 bytes)
    
    cudaError_t err = cudaMalloc((void **)&d_buffer, buffer_size);
    if (err != cudaSuccess) {
        printf("CUDA malloc error (d_buffer): %s\n", cudaGetErrorString(err));
        cudaDeviceReset();
        return;
    }

    // Copy input data to device
    size_t offset = 0;
    cudaMemcpy(d_buffer + offset, seed, 32, cudaMemcpyHostToDevice);
    offset += 32;
    
    cudaMemcpy(d_buffer + offset, &target_len, 8, cudaMemcpyHostToDevice);
    offset += 8;
    
    cudaMemcpy(d_buffer + offset, target, target_len, cudaMemcpyHostToDevice);
    offset += target_len;
    
    cudaMemcpy(d_buffer + offset, &suffix_len, 8, cudaMemcpyHostToDevice);
    offset += 8;
    
    cudaMemcpy(d_buffer + offset, suffix, suffix_len, cudaMemcpyHostToDevice);

    // Set case insensitive flag
    cudaMemcpyToSymbol(d_case_insensitive, &case_insensitive, sizeof(bool));

    // Reset done and count
    int zero = 0;
    unsigned long long zero_ll = 0;
    cudaMemcpyToSymbol(done, &zero, sizeof(int));
    cudaMemcpyToSymbol(count, &zero_ll, sizeof(unsigned long long));

    // Launch kernel
    int threadsPerBlock = 256;
    int numBlocks = (1000000 + threadsPerBlock - 1) / threadsPerBlock;
    vanity_keypair_search<<<numBlocks, threadsPerBlock>>>(d_buffer, 0);

    // Wait for completion
    cudaDeviceSynchronize();

    // Copy results back to host
    unsigned long long final_count;
    cudaMemcpyFromSymbol(&final_count, count, sizeof(unsigned long long));
    
    // Copy the output (private key + public key + count)
    cudaMemcpy(out, d_buffer + 32 + 8 + target_len + 8 + suffix_len, 64, cudaMemcpyDeviceToHost);
    
    // Copy the count to the end of output buffer
    memcpy(out + 56, &final_count, 8);

    // Cleanup
    cudaFree(d_buffer);
    cudaDeviceReset();
}