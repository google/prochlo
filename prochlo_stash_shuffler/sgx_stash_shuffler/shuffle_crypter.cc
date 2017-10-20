// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <algorithm>
#include <vector>

#include <string>
#include "Enclave.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/pem.h"
#include "sgx_trts.h" /* for sgx_read_rand */
#include "shuffle_crypter.h"
#include "string.h"

void RAND_bytes(uint8_t* out, unsigned int out_len) {
  // need to use sgx_read_rand instead of rand()
  unsigned int j;
  if (SGX_SUCCESS != sgx_read_rand(out, out_len)) {
    log_printf(LOG_ERROR, "sgx_read_rand failed\n");
  }
}

#include "Enclave_t.h"

namespace prochlo {
namespace shuffler {
namespace crypto {

ShuffleCrypter::ShuffleCrypter(const std::string& private_key_pem)
    : key_(nullptr) {
  // Load my own keypair.
  //
  // NOTE: In this demo, we use a hack to obtain the Shuffler's own key pair, by
  // providing it, from untrusted code, to the Shuffler, which is not secure of
  // course. In an actual use of this code in production, the Shuffler creates a
  // key pair when it starts up, and it attests to its created public key in a
  // certificate, which it provides to the untrusted portion of the Shuffler for
  // publishing (e.g., on a web page or a PKI). Clients fetch that certificate
  // and obtain the shuffler's public key, but only the Shuffler enclave itself
  // knows the corresponding private key.
  key_ = LoadPrivateKeyPEM(private_key_pem);
  CHECK_NE(key_, nullptr);

  RAND_bytes(intermediate_aesgcm_key_, SGX_AESGCM_KEY_SIZE);
  CHECK_EQ(SGX_AESGCM_KEY_SIZE, kSymmetricKeyLength);
}

ShuffleCrypter::ShuffleCrypter(const std::string& private_key_pem,
                               const uint8_t* symmetric_key)
    : key_(nullptr) {
  key_ = LoadPrivateKeyPEM(private_key_pem);
  CHECK_NE(key_, nullptr);

  memcpy(intermediate_aesgcm_key_, symmetric_key, kSymmetricKeyLength);
  CHECK_EQ(SGX_AESGCM_KEY_SIZE, kSymmetricKeyLength);
}

int OpenSSLPrintCallback(const char* str, size_t len, void* ctx) {
  log_printf(LOG_ERROR, "->%s\n", str);
  return 1;
}

EVP_PKEY* ShuffleCrypter::LoadPrivateKeyPEM(const std::string& key_pem) {
  BIO* bo = BIO_new(BIO_s_mem());
  BIO_write(bo, key_pem.c_str(), key_pem.length());

  EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bo, nullptr, nullptr, nullptr);
  BIO_free(bo);

  CHECK_NE(pkey, nullptr);

  return pkey;
}

EVP_PKEY* ShuffleCrypter::LoadPublicKeyDER(const uint8_t* key_bytes,
                                           size_t length) {
  EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &key_bytes, length);
  CHECK_NE(pkey, nullptr);

  return pkey;
}

void ShuffleCrypter::DeriveSecretSymmetricKey(EVP_PKEY* local_key,
                                              EVP_PKEY* peer_public_key,
                                              uint8_t* secret_key) {
  CHECK_NE(nullptr, local_key);
  CHECK_NE(nullptr, peer_public_key);
  CHECK_NE(nullptr, secret_key);

  EVP_PKEY_CTX* ctx = nullptr;

  ctx = EVP_PKEY_CTX_new(local_key, /*e=*/nullptr);
  CHECK_NE(nullptr, ctx);

  CHECK_EQ(1, EVP_PKEY_derive_init(ctx));

  CHECK_EQ(1, EVP_PKEY_derive_set_peer(ctx, peer_public_key));

  size_t derived_secret_length = 0;
  CHECK_EQ(1, EVP_PKEY_derive(ctx, nullptr, &derived_secret_length));
  CHECK_LE(derived_secret_length, kSharedSecretLength);

  uint8_t derived_secret[kSharedSecretLength];
  CHECK_EQ(1, EVP_PKEY_derive(ctx, derived_secret, &derived_secret_length));

  // Now turn it into a key, using a HKDF.
  // 1. Extract
  uint8_t expansion[kSharedSecretExpansionLength];
  // Zero it out, don't use a fancy salt.
  memset(expansion, 0, kSharedSecretExpansionLength);
  // First HMAC the shared secret with the expansion as the key (initially
  // zero).
  uint32_t hmac_length;
  uint8_t* hmac = HMAC(EVP_sha256(),
                       /* key = */ expansion, kSharedSecretExpansionLength,
                       /* d = */ derived_secret, derived_secret_length,
                       /* md = */ expansion, &hmac_length);
  CHECK_NE(nullptr, hmac);
  CHECK_EQ(hmac_length, kSharedSecretExpansionLength);
  // Now HMAC the previous HMAC result with itself as a key, and some
  // well-defined additional data (namely, 1).
  uint8_t one = 1;
  hmac = HMAC(EVP_sha256(),
              /* key = */ expansion, kSharedSecretExpansionLength,
              /* d = */ &one, sizeof(one),                   // arbitrary choice
              /* md = */ expansion, /* md_len= */ nullptr);  // No need to
                                                             // obtain the
                                                             // length of the
                                                             // md yet again.
  CHECK_NE(nullptr, hmac);

  // Now we have good key material in |expansion|. Strip it down to the
  // keysize of AES128.
  CHECK_GE(kSharedSecretExpansionLength, kSymmetricKeyLength);
  memcpy(secret_key, expansion, kSymmetricKeyLength);

  EVP_PKEY_CTX_free(ctx);
}

void ShuffleCrypter::ShuffleIndexArray(
    std::vector<size_t, AppendOnlyAllocator<size_t>>* array, size_t length) {
  // This was adapted from std::random_shuffle in stlport, the C++ standard
  // library used by the SGX SDK originally. The current library (libtcxx)
  // doesn't support std::random_shuffle or std::shuffle at all.
  std::vector<size_t>::iterator begin = array->begin();
  std::vector<size_t>::iterator end = begin + length;
  for (auto i = begin + 1; i != end; ++i) {
    size_t distance;
    auto result = sgx_read_rand(reinterpret_cast<unsigned char*>(&distance),
                                sizeof(size_t));
    CHECK_EQ(result, SGX_SUCCESS);
    size_t random_magnitude = (i - begin) + 1;
    distance = abs(distance) % random_magnitude;
    std::iter_swap(i, begin + distance);
  }
}

bool ShuffleCrypter::DecryptShufflerItem(
    const ShufflerItem& shuffler_item, PlainShufflerItem* plain_shuffler_item) {
  CHECK_NE(nullptr, plain_shuffler_item);

  EVP_PKEY* peer_public_key =
      LoadPublicKeyDER(shuffler_item.client_public_key, kPublicKeyLength);
  CHECK_NE(nullptr, peer_public_key);

  uint8_t derived_secret_key[kSymmetricKeyLength];
  DeriveSecretSymmetricKey(key_, peer_public_key, derived_secret_key);

  EVP_PKEY_free(peer_public_key);

  sgx_aes_gcm_128bit_key_t* p_key =
      static_cast<sgx_aes_gcm_128bit_key_t*>(&derived_secret_key);
  uint8_t p_dst[kPlainShufflerItemLength];
  uint32_t src_len = kPlainShufflerItemLength;
  const uint8_t* p_src = shuffler_item.ciphertext;
  const uint8_t* p_iv = shuffler_item.nonce;
  uint32_t iv_len = kNonceLength;
  uint8_t* p_aad = nullptr;
  uint32_t aad_len = 0;
  const sgx_aes_gcm_128bit_tag_t* p_in_mac = &shuffler_item.tag;
  CHECK_EQ(SGX_AESGCM_MAC_SIZE, kTagLength);

  CHECK_EQ(SGX_SUCCESS,
           sgx_rijndael128GCM_decrypt(p_key, p_src, src_len, p_dst, p_iv,
                                      iv_len, p_aad, aad_len, p_in_mac));

  CHECK_EQ(kPlainShufflerItemLength,
           plain_shuffler_item->Read(p_dst, kPlainShufflerItemLength));
  return true;
}

bool ShuffleCrypter::EncryptIntermediateShufflerItem(
    const PlainIntermediateShufflerItem& plain_intermediate_shuffler_item,
    IntermediateShufflerItem* intermediate_shuffler_item) {
  CHECK_NE(nullptr, intermediate_shuffler_item);

  uint8_t plaintext[kIntermediateShufflerPlaintextSize];
  size_t plaintext_length = plain_intermediate_shuffler_item.Write(
      plaintext, kIntermediateShufflerPlaintextSize);

  // Now lay out the ciphertext. First the nonce, and then the ciphertext
  // itself.
  uint8_t* ciphertext = intermediate_shuffler_item->ciphertext;

  RAND_bytes(intermediate_shuffler_item->nonce, kNonceLength);

  sgx_status_t rc = SGX_SUCCESS;
  const sgx_aes_gcm_128bit_key_t* p_key =
      (const sgx_aes_gcm_128bit_key_t*)intermediate_aesgcm_key_;
  const uint8_t* p_src = (uint8_t*)plaintext;
  uint32_t src_len = plaintext_length;
  uint8_t* p_dst = ciphertext;

  uint8_t* p_aad = NULL;
  uint32_t aad_len = 0;
  sgx_aes_gcm_128bit_tag_t* p_in_mac =
      (sgx_aes_gcm_128bit_tag_t*)intermediate_shuffler_item->tag;

  rc = sgx_rijndael128GCM_encrypt(p_key, p_src, src_len, p_dst,
                                  intermediate_shuffler_item->nonce,
                                  kNonceLength, p_aad, aad_len, p_in_mac);

  if (rc != SGX_SUCCESS) {
    log_printf(LOG_ERROR, "sgx_rijndael128GCM_encrypt failed, rc=%d\n", rc);
  }

  return true;
}

bool ShuffleCrypter::DecryptIntermediateShufflerItem(
    const IntermediateShufflerItem& intermediate_shuffler_item,
    PlainIntermediateShufflerItem* plain_intermediate_shuffler_item) {
  CHECK_NE(nullptr, plain_intermediate_shuffler_item);

  uint8_t plaintext[kIntermediateShufflerPlaintextSize];
  size_t plaintext_length = kIntermediateShufflerPlaintextSize;

  sgx_status_t rc = SGX_SUCCESS;
  const sgx_aes_gcm_128bit_key_t* p_key =
      (const sgx_aes_gcm_128bit_key_t*)intermediate_aesgcm_key_;
  const uint8_t* p_src = intermediate_shuffler_item.ciphertext;
  uint32_t src_len = kIntermediateShufflerPlaintextSize;
  uint8_t* p_dst = (uint8_t*)plaintext;

  const uint8_t* p_iv = intermediate_shuffler_item.nonce;
  uint32_t iv_len = kNonceLength;
  uint8_t* p_aad = nullptr;
  uint32_t aad_len = 0;
  const sgx_aes_gcm_128bit_tag_t* p_in_mac =
      (sgx_aes_gcm_128bit_tag_t*)intermediate_shuffler_item.tag;

  rc = sgx_rijndael128GCM_decrypt(p_key, p_src, src_len, p_dst, p_iv, iv_len,
                                  p_aad, aad_len, p_in_mac);

  if (rc != SGX_SUCCESS) {
    if (rc == SGX_ERROR_MAC_MISMATCH)
      log_printf(LOG_ERROR, "sgx_rijndael128GCM_decrypt tag match failed\n");
    else
      log_printf(LOG_ERROR, "sgx_rijndael128GCM_decrypt failed, rc=%d\n", rc);
  }
  plain_intermediate_shuffler_item->Read(plaintext, plaintext_length);

  return true;
}

// static
size_t ShuffleCrypter::RandomSizeT(size_t limit) {
  size_t value = 0;
  RAND_bytes(reinterpret_cast<uint8_t*>(&value), sizeof(size_t));
  return value % limit;
}


};  // namespace crypto
};  // namespace shuffler
};  // namespace prochlo
