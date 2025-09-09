#include "base58.h"

__device__ uint8_t const base58_chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// ci = case insensitive (map all uppercase to lowercase except for L)
__device__ uint8_t const base58_chars_ci[] = "123456789abcdefghjkLmnpqrstuvwxyzabcdefghijkmnopqrstuvwxyz";

#define N 32
#define INTERMEDIATE_SZ (9UL)
#define BINARY_SZ ((ulong)N / 4UL)

__device__ uint const enc_table_32[BINARY_SZ][INTERMEDIATE_SZ - 1UL] = {
    {513735U, 77223048U, 437087610U, 300156666U, 605448490U, 214625350U, 141436834U, 379377856U},
    {0U, 78508U, 646269101U, 118408823U, 91512303U, 209184527U, 413102373U, 153715680U},
    {0U, 0U, 11997U, 486083817U, 3737691U, 294005210U, 247894721U, 289024608U},
    {0U, 0U, 0U, 1833U, 324463681U, 385795061U, 551597588U, 21339008U},
    {0U, 0U, 0U, 0U, 280U, 127692781U, 389432875U, 357132832U},
    {0U, 0U, 0U, 0U, 0U, 42U, 537767569U, 410450016U},
    {0U, 0U, 0U, 0U, 0U, 0U, 6U, 356826688U},
    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}
};

#define RAW58_SZ (INTERMEDIATE_SZ * 5UL)

__device__ ulong fd_base58_encode_32(uint8_t *bytes, uint8_t *out, bool case_insensitive) {
    uint8_t const *alphabet = case_insensitive ? base58_chars_ci : base58_chars;
    
    // Convert binary to intermediate representation
    ulong intermediate[INTERMEDIATE_SZ];
    for (ulong i = 0; i < INTERMEDIATE_SZ; i++) intermediate[i] = 0UL;
    
    for (ulong i = 0UL; i < BINARY_SZ; i++) {
        uint binary_chunk = ((uint)bytes[4*i+3]) | (((uint)bytes[4*i+2]) << 8) | 
                           (((uint)bytes[4*i+1]) << 16) | (((uint)bytes[4*i]) << 24);
        
        for (ulong j = 0UL; j < INTERMEDIATE_SZ - 1UL; j++) {
            ulong carry = (ulong)binary_chunk * (ulong)enc_table_32[i][j];
            ulong k = j;
            while (carry) {
                carry += intermediate[k];
                intermediate[k] = carry % 656356768UL;
                carry /= 656356768UL;
                k++;
            }
        }
    }
    
    // Convert intermediate to base58
    uint8_t raw58[RAW58_SZ];
    for (ulong i = 0UL; i < INTERMEDIATE_SZ; i++) {
        ulong v = intermediate[INTERMEDIATE_SZ - 1UL - i];
        for (ulong j = 0UL; j < 5UL; j++) {
            raw58[5UL * i + j] = (uint8_t)(v % 58UL);
            v /= 58UL;
        }
    }
    
    // Find first non-zero
    ulong first_nonzero = RAW58_SZ;
    for (ulong i = RAW58_SZ; i > 0UL; i--) {
        if (raw58[i - 1UL]) {
            first_nonzero = i - 1UL;
            break;
        }
    }
    
    // Count leading zeros in input
    ulong leading_zeros = 0UL;
    for (ulong i = 0UL; i < N; i++) {
        if (bytes[i]) break;
        leading_zeros++;
    }
    
    // Output the result
    ulong out_len = 0UL;
    
    // Add '1' for each leading zero
    for (ulong i = 0UL; i < leading_zeros; i++) {
        out[out_len++] = alphabet[0];
    }
    
    // Add the base58 digits
    if (first_nonzero < RAW58_SZ) {
        for (ulong i = first_nonzero; i < RAW58_SZ; i++) {
            out[out_len++] = alphabet[raw58[RAW58_SZ - 1UL - i]];
        }
    }
    
    return out_len;
}