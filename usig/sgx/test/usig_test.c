// Copyright (c) 2018 NEC Laboratories Europe GmbH.
//
// Authors: Sergey Fedorov <sergey.fedorov@neclab.eu>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#undef NDEBUG // make sure `assert()` is not an empty macro
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sgx_tcrypto.h>
#include "usig.h"

//int secret_size=32;
const char *enclave_file;
uint8_t key[16]={0};
#define IRREDUCTIBLE_POLY 0x011b

uint8_t **MULTIPLICATIVE_INVERSE_TABLE = NULL;
const int n=3,k=2,secret_size=32;
// Add two polynomials in GF(2^8)
uint8_t p_add(uint8_t a, uint8_t b) {
    return a ^ b;
}

// Multiply a polynomial by x in GF(2^8)
uint8_t time_x(uint8_t a) {
    if ((a >> 7) & 0x1) {
        return (a << 1) ^ IRREDUCTIBLE_POLY;
    } else {
        return (a << 1);
    }
}

uint8_t time_x_power(uint8_t a, uint8_t x_power) {
    uint8_t res = a;
    for (; x_power > 0; x_power--) {
        res = time_x(res);
    }
    return res;
}

// Multiply two polynomials in GF(2^8)
uint8_t p_mul(uint8_t a, uint8_t b) {
    uint8_t res = 0;
    for (int degree = 7; degree >= 0; degree--) {
        if ((b >> degree) & 0x1) {
            res = p_add(res, time_x_power(a, degree));
        }
    }
    return res;
}

uint8_t p_inv(uint8_t a) {
    
    // Build the table so that table[a][1] = inv(a)
    if (MULTIPLICATIVE_INVERSE_TABLE == NULL) {
        MULTIPLICATIVE_INVERSE_TABLE = (uint8_t **) malloc(256 * sizeof(uint8_t *));
        for (int row = 0; row < 256; row++) {
            MULTIPLICATIVE_INVERSE_TABLE[row] = (uint8_t *) malloc(256 * sizeof(uint8_t));
            
            for (int col = 0; col < 256; col++) {
                MULTIPLICATIVE_INVERSE_TABLE[row][p_mul(row, col)] = col;
            }
        }
    }
    
    return MULTIPLICATIVE_INVERSE_TABLE[a][1];
}

// Divide two polynomials in GF(2^8)
uint8_t p_div(uint8_t a, uint8_t b) {
    return p_mul(a, p_inv(b));
}

uint8_t rand_byte() {
    	int r=rand();
		return r%0xff;
}

uint8_t * make_random_poly(int degree, uint8_t secret) {
    uint8_t *poly = malloc((degree + 1) * sizeof(uint8_t));
    for (; degree > 0; degree--) {
        poly[degree] = rand_byte();
    }
    poly[0] = secret;
    return poly;
}

uint8_t poly_eval(uint8_t *poly, int degree , uint8_t x) {
    uint8_t res = 0;
    for (; degree >= 0; degree--) {
        uint8_t coeff = poly[degree];
        uint8_t term = 0x01;
        for (int times = degree; times > 0; times--) {
            term = p_mul(term, x);
        }
        res = p_add(res, p_mul(coeff, term));
    }
    return res;
}
char * arr_to_hex_str(uint8_t *arr, int arr_size) {
  char *out = malloc(2 * arr_size + 1);
  for (int pos = 0; pos < arr_size; pos++) {
    sprintf(out + 2*pos, "%02x", arr[pos]);
  }
  out[2 * arr_size + 1] = 0x00;
  return out;
}



uint8_t * hex_str_to_arr(const char *s) {
  // / 2 ?
  uint8_t *res = malloc(strlen(s) * sizeof(uint8_t));
  char buff[3] = {0x00, 0x00, 0x00};
  for (int pos = 0; pos <(int) strlen(s); pos++) {
    strncpy(buff, s + pos*2, 2);
    res[pos] = strtoul(buff, NULL, 16);
  }
  return res;
}
// Interpolate a (k-1) degree polynomial and evaluate it at x = 0
uint8_t poly_interpolate(uint8_t *xs, uint8_t *ys, int k) {
    uint8_t res = 0;
    
    for (int j = 0; j < k; j++) {
        uint8_t prod = 0x01;
        for (int m = 0; m < k; m++) {
            if (m != j) {
                prod = p_mul(prod, p_div(xs[m], p_add(xs[m], xs[j])));
            }
        }
        res = p_add(res, p_mul(ys[j], prod));
    }
    return res;
}
int  generate_secret(int secret_size, int n, int k,uint8_t *shares) {
    //uint8_t secret[32]=rand();
    //
    //uint8_t * secret=malloc(sizeof(uint8_t)*secret_size);
    //sgx_read_rand((void *)secret, sizeof(uint8_t)*secret_size);
    uint8_t secret[32]="hello";
    for(int i=0;i<n;i++)
    {
        shares[i*(secret_size+1)]=rand_byte();
    }
    for (int secret_idx = 0; secret_idx < secret_size; secret_idx++) {
        uint8_t *poly = make_random_poly(k-1, secret[secret_idx]);
        
        // Evaluate poly on every one of the n x points
        for (int i = 0; i < n; i++) {
            shares[i*(secret_size+1)+secret_idx + 1] = poly_eval(poly, k-1, shares[i*(secret_size+1)+0]);
        }
    }
    
    return 1;
}

int join(uint8_t *shares, int secret_size, int k,uint8_t *secret ) {
    
    for (int secret_idx = 1; secret_idx <= secret_size; secret_idx++) {
        uint8_t *xs = (uint8_t *) malloc(k * sizeof(uint8_t));
        uint8_t *ys = (uint8_t *) malloc(k * sizeof(uint8_t));
        for (int i = 0; i < k; i++) {
            xs[i] = shares[i*(secret_size+1)+0];
            ys[i] = shares[i*(secret_size+1)+secret_idx];
            
            secret[secret_idx-1] = poly_interpolate(xs, ys, k);
        }
    }
    
    return 1;
}

   static void test_init_destroy()
{
        sgx_enclave_id_t eid;

        assert(usig_init(enclave_file, &eid,key, NULL, 0) == SGX_SUCCESS);
        assert(usig_destroy(eid) == SGX_SUCCESS);
}

static inline bool signature_is_equal(sgx_ec256_signature_t *s1,
                                      sgx_ec256_signature_t *s2)
{
        return memcmp(s1, s2, sizeof(sgx_ec256_signature_t)) == 0;
}

static void test_seal_key()
{
        sgx_enclave_id_t usig;
        void *sealed_data;
        size_t sealed_data_size;

        assert(usig_init(enclave_file, &usig,key, NULL, 0) == SGX_SUCCESS);
        assert(usig_seal_key(usig, &sealed_data,
                             &sealed_data_size) == SGX_SUCCESS);
        assert(usig_destroy(usig) == SGX_SUCCESS);
        assert(usig_init(enclave_file, &usig, key,sealed_data,
                         sealed_data_size) == SGX_SUCCESS);
        free(sealed_data);
        assert(usig_destroy(usig) == SGX_SUCCESS);
}

static void test_create_ui()
{
        sgx_enclave_id_t usig,usig1,usig2;
        uint64_t e1, e2;
        void *sealed_data;
        size_t sealed_data_size;
        sgx_ec256_signature_t s1,  s3;
        uint64_t c1, c3;
        sgx_sha256_hash_t digest = "TEST DIGEST";
		assert(usig_init(enclave_file, &usig, key,NULL, 0) == SGX_SUCCESS);
        assert(usig_seal_key(usig, &sealed_data,
                             &sealed_data_size) == SGX_SUCCESS);
        assert(usig_get_epoch(usig, &e1) == SGX_SUCCESS);
		uint8_t* encrypted_shares_0=malloc(sizeof(uint8_t)*100);
		uint8_t* encrypted_secret_h_0=malloc(sizeof(uint8_t)*32);
        assert(usig_create_ui(usig, digest, &c1, &s1,encrypted_shares_0,encrypted_secret_h_0) == SGX_SUCCESS);
        // The first counter value must be one
        assert(c1 == 1);
		assert(usig_init(enclave_file, &usig1, key,NULL, 0) == SGX_SUCCESS);
		uint8_t * shares_0=malloc(sizeof(uint8_t)*(secret_size+1));
		memset(shares_0,0,sizeof(uint8_t)*(secret_size+1));
		sgx_sha256_hash_t secret_h;
		assert(usig_verify_ui(usig1,digest,&s1,encrypted_secret_h_0,encrypted_shares_0,shares_0,secret_h)==SGX_SUCCESS);
		printf("share1: %s\n", arr_to_hex_str(shares_0, secret_size + 1));
		
		assert(usig_init(enclave_file, &usig2, key,NULL, 0) == SGX_SUCCESS);
		uint8_t * shares_1=malloc(sizeof(uint8_t)*(secret_size+1));
        memset(shares_1,0,sizeof(uint8_t)*(secret_size+1));
        assert(usig_verify_ui(usig2,digest,&s1,encrypted_secret_h_0,encrypted_shares_0+secret_size+1,shares_1,secret_h)==SGX_SUCCESS);
        printf("share2: %s\n", arr_to_hex_str(shares_1, secret_size + 1));
		printf("secret hash: %s\n",arr_to_hex_str(secret_h,32));
		//printf("should be 0ee8c396eb4005554d2ee590de052203711496512b848db0dd8a380df0fcde20\n");
    	//memset(counter,0,sizeof(uint8_t)*secret_size);	

        //assert(usig_create_ui(usig, digest, &c2, &s2,encrypted_shares,encrypted_secret_h) == SGX_SUCCESS);
        // The counter must be monotonic and sequential
        //assert(c2 == c1 + 1);
        // Certificate must be unique for each counter value
        //assert(!signature_is_equal(&s1, &s2));

        // Destroy USIG instance
        assert(usig_destroy(usig) == SGX_SUCCESS);

        // Recreate USIG using the sealed secret from the first instance
        assert(usig_init(enclave_file, &usig, key,sealed_data,
                         sealed_data_size) == SGX_SUCCESS);
        assert(usig_get_epoch(usig, &e2) == SGX_SUCCESS);
		uint8_t* encrypted_shares_1=malloc(sizeof(uint8_t)*100);
        uint8_t* encrypted_secret_h_1=malloc(sizeof(uint8_t)*32);

        assert(usig_create_ui(usig, digest, &c3, &s3,encrypted_shares_1,encrypted_secret_h_1) == SGX_SUCCESS);
        // Must fetch a fresh counter value
        assert(c3 == 1);

        // Check for uniqueness of the epoch and certificate produced
        // by the new instance of the enclave
        assert(e1 != e2);
        assert(!signature_is_equal(&s1, &s3));

        assert(usig_destroy(usig) == SGX_SUCCESS);
        free(sealed_data);
}

static void test_secret_sharing()
{
        sgx_enclave_id_t usig;
       // int secret_size=32;
        
        
        uint8_t *shares=malloc(sizeof(uint8_t)*100);
       
        assert(usig_init(enclave_file, &usig,key, NULL, 0) == SGX_SUCCESS);

       // assert(usig_generate_secret(usig, secret_size,n,k,
                           //  shares) == SGX_SUCCESS);
//	puts((char*)shares);	
        assert(usig_destroy(usig) == SGX_SUCCESS);
     free(shares); 
}
int main(int argc, const char **argv)
{
        assert(argc == 2);
        enclave_file = argv[1];

        test_init_destroy();
        test_seal_key();
        test_create_ui();
		test_secret_sharing();
        puts("PASS");
}
