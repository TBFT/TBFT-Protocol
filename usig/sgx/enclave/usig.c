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

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_tcrypto.h>

#include "usig_t.h"

static sgx_ec256_private_t usig_priv_key;
static sgx_ec256_public_t usig_pub_key;
static sgx_aes_ctr_128bit_key_t aes_key;
static uint64_t usig_epoch;
static uint64_t usig_counter = 1;
static bool initialized;
#define IRREDUCTIBLE_POLY 0x011b
const int n=3,k=2,secret_size=16;


typedef struct __attribute__((__packed__)) {
    sgx_sha256_hash_t digest;
    uint64_t epoch;
    uint64_t counter;
} usig_cert_data_t;

static uint8_t **MULTIPLICATIVE_INVERSE_TABLE = NULL;

uint8_t p_add(uint8_t a, uint8_t b) {
    return a ^ b;
}

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

uint8_t p_div(uint8_t a, uint8_t b) {
    return p_mul(a, p_inv(b));
}

uint8_t rand_byte() {
    	uint8_t  res;
    	sgx_status_t  ret = sgx_read_rand((void *)&res, sizeof(res));
        if (ret != SGX_SUCCESS) {
                return 0;
        }
	return res;

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
sgx_status_t  ecall_usig_generate_secret(int secret_size, int n, int k,uint8_t *encrypted_shares,uint8_t *encrypted_secret_h) {

    uint8_t * shares=malloc(sizeof(uint8_t)*(secret_size+1)*n);
    uint8_t secret[16]="";
	sgx_read_rand((void *)secret, sizeof(uint8_t)*secret_size);
    
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
		free(poly);
    }

	uint8_t counter[secret_size];
    for(int i=0;i<n;i++){
	    memset(counter,0,sizeof(uint8_t)*secret_size);
        sgx_aes_ctr_encrypt(&aes_key,shares+i*(secret_size+1),secret_size+1,counter,secret_size,encrypted_shares+i*(secret_size+1));
    }
	sgx_sha256_hash_t secret_h; 
    sgx_sha256_msg(secret,secret_size,&secret_h);
	memset(counter,0,sizeof(uint8_t)*secret_size);
	sgx_aes_ctr_encrypt(&aes_key,secret_h,sizeof(secret_h),counter,secret_size,encrypted_secret_h);
	free(shares);
    return SGX_SUCCESS;
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

sgx_status_t ecall_usig_create_ui(sgx_sha256_hash_t digest,
                                  uint64_t *counter,
                                  sgx_ec256_signature_t *signature,uint8_t *encrypted_shares,uint8_t *encrypted_secret_h){
    sgx_status_t ret;
    sgx_ecc_state_handle_t ecc_handle;
    sgx_ec256_signature_t signature_buf;
    usig_cert_data_t data;

    if (!initialized) {
        ret = SGX_ERROR_UNEXPECTED;
        goto close_context;
    }
    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS) {
        goto close_context;
    }

    memcpy(data.digest, digest, sizeof(data.digest));
    *counter = data.counter = usig_counter;

    ret = sgx_ecdsa_sign((uint8_t *)&data, sizeof(data),
                             &usig_priv_key, &signature_buf, ecc_handle);
        if (ret != SGX_SUCCESS) {
                goto close_context;
        }
        // Increment the internal counter just before going to expose
        // a valid signature to the untrusted world. That makes sure
        // the counter value cannot be reused to sign another message.
        usig_counter++;
        memcpy(signature, &signature_buf, sizeof(signature_buf));
		ret=ecall_usig_generate_secret(secret_size,n,k,encrypted_shares,encrypted_secret_h);
		if (ret != SGX_SUCCESS) {
			goto close_context;
		}

close_context:
    sgx_ecc256_close_context(ecc_handle);

        return ret;
}

sgx_status_t ecall_usig_verify_ui(sgx_sha256_hash_t digest,sgx_ec256_signature_t *signature,uint8_t* encrypted_secret_h, uint8_t* encrypted_share, uint8_t * shares,sgx_sha256_hash_t secret_h)
{
		sgx_status_t ret=SGX_SUCCESS;
        sgx_ecc_state_handle_t ecc_handle;
        usig_cert_data_t data;

        if (!initialized) {
            ret = SGX_ERROR_UNEXPECTED;
            return ret;
        }
		ret = sgx_ecc256_open_context(&ecc_handle);
		if (ret != SGX_SUCCESS) {
            return ret;
        }
		memcpy(data.digest, digest, sizeof(data.digest));
        data.counter = usig_counter;
		uint8_t result;
		ret = sgx_ecdsa_verify((uint8_t *)&data,sizeof(data),&usig_pub_key,signature,&result,ecc_handle);

		uint8_t cc[secret_size];
		ret = sgx_aes_ctr_decrypt(&aes_key,encrypted_share,secret_size+1,cc,secret_size,shares);
		if(ret != SGX_SUCCESS) {
            return ret;
        }
        ret = sgx_aes_ctr_decrypt(&aes_key,encrypted_secret_h,secret_size*sizeof(uint8_t),cc,secret_size,secret_h);
        if(ret != SGX_SUCCESS) {
            return ret;
        }

		  sgx_ecc256_close_context(ecc_handle);
        return ret;

	
}

sgx_status_t ecall_usig_get_epoch(uint64_t *epoch)
{
        if (!initialized) {
                return SGX_ERROR_UNEXPECTED;
        }

        *epoch = usig_epoch;
        return SGX_SUCCESS;
}

sgx_status_t ecall_usig_get_pub_key(sgx_ec256_public_t *pub_key)
{
        if (!initialized) {
                return SGX_ERROR_UNEXPECTED;
        }

        memcpy(pub_key, &usig_pub_key, sizeof(usig_pub_key));
        return SGX_SUCCESS;
}

sgx_status_t ecall_usig_get_sealed_key_size(uint32_t *size)
{
        *size = sgx_calc_sealed_data_size(sizeof(usig_pub_key), sizeof(usig_priv_key));
        return SGX_SUCCESS;
}

sgx_status_t ecall_usig_seal_key(void *sealed_data, uint32_t sealed_data_size)
{
        if (!initialized) {
                return SGX_ERROR_UNEXPECTED;
        }

        return sgx_seal_data(sizeof(usig_pub_key), (void *)&usig_pub_key,
                            sizeof(usig_priv_key), (void *)&usig_priv_key,
                            sealed_data_size, sealed_data);
}

static sgx_status_t generate_key(void)
{
        sgx_status_t ret;
        sgx_ecc_state_handle_t ecc_handle;

        ret = sgx_ecc256_open_context(&ecc_handle);
        if (ret != SGX_SUCCESS) {
                goto out;
        }

        // Create an key pair to produce USIG certificates.
        ret = sgx_ecc256_create_key_pair(&usig_priv_key, &usig_pub_key, ecc_handle);
        if (ret != SGX_SUCCESS) {
                goto close_context;
        }

close_context:
        sgx_ecc256_close_context(ecc_handle);
out:
        return ret;
}

static sgx_status_t unseal_key(void *data, uint32_t size)
{
        sgx_status_t ret;
        uint32_t pub_key_size = sizeof(usig_pub_key);
        uint32_t priv_key_size = sizeof(usig_priv_key);

        if (size != sgx_calc_sealed_data_size(pub_key_size, priv_key_size)) {
                ret = SGX_ERROR_UNEXPECTED;
                goto out;
        }

        ret = sgx_unseal_data((sgx_sealed_data_t *)data,
                               (void *)&usig_pub_key, &pub_key_size,
                               (void *)&usig_priv_key, &priv_key_size);
        if (ret != SGX_SUCCESS) {
                goto out;
        }

        if (pub_key_size != sizeof(usig_pub_key) ||
            priv_key_size != sizeof(usig_priv_key)) {
                ret =  SGX_ERROR_UNEXPECTED;
                goto out;
        }

out:
        return ret;
}

sgx_status_t ecall_usig_init(uint8_t * key, void *sealed_data, uint32_t sealed_data_size)
{
        sgx_status_t ret;

        if (initialized) {
                ret = SGX_ERROR_UNEXPECTED;
                goto out;
        }
        memcpy(aes_key,key,16*sizeof(uint8_t));
        

        // Create a random epoch value. Each instance of USIG should
        // have a unique epoch value to be able to guarantee unique,
        // sequential and monotonic counter values given an epoch
        // value.
        ret = sgx_read_rand((void *)&usig_epoch, sizeof(usig_epoch));
        if (ret != SGX_SUCCESS) {
                goto out;
        }

        ret = sealed_data != NULL ?
                unseal_key(sealed_data, sealed_data_size) :
                generate_key();
        if (ret != SGX_SUCCESS) {
                goto out;
        }

        initialized = true;

out:
        return ret;
}
