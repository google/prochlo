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

#ifndef __SGX_STASH_SHUFFLER_SHUFFLE_CRYPTER_H__
#define __SGX_STASH_SHUFFLER_SHUFFLE_CRYPTER_H__

#include <random>
#include <vector>

#include "openssl/evp.h"
#include "sgx_tcrypto.h"
#include "shuffle_data.h"

namespace prochlo {
namespace shuffler {
namespace crypto {

constexpr size_t kShufflerKeyLength = 32;

// This class collects cryptographic primitives for use by the shuffler. It is a
// class (as opposed to a collection of functions) primarily to enable mocking
// for the purposes of predictable testing.
class ShuffleCrypter {
 public:
  // The constructor takes the PEM-formatted private key of the Shuffler. This
  // is typically generated when the Shuffler starts up and saved or sealed to
  // disk until the Shuffler restarts.
  ShuffleCrypter(const std::string& private_key_pem);

  // This is a constructor used for testing. It is given the symmetric key for
  // encrypting intermediate shuffler items explicitly, rather than randomly
  // picking one upon construction. |symmetric_key| must not be NULL and
  // |*symmetric_key| must have at least |kSymmetricKeyLength| bytes allocated.
  ShuffleCrypter(const std::string& private_key_pem,
                 const uint8_t* symmetric_key);
  virtual ~ShuffleCrypter() {}

  // Shuffles the |length|-sized prefix of |array| in place. |array| may not be
  // NULL.
  virtual void ShuffleIndexArray(std::vector<size_t>* array, size_t length);

  virtual bool DecryptShufflerItem(const ShufflerItem& shuffler_item,
                                   PlainShufflerItem* plain_shuffler_item);

  // Encrypt/decrypt a plaintext shuffler item, given the already initialized
  // |shuffle_ctx_|. Returns INTERNAL_ERROR if encryption/decryption fails.
  virtual bool EncryptIntermediateShufflerItem(
      const PlainIntermediateShufflerItem& plain_intermediate_shuffler_item,
      IntermediateShufflerItem* intermediate_shuffler_item);

  virtual bool DecryptIntermediateShufflerItem(
      const IntermediateShufflerItem& intermediate_shuffler_item,
      PlainIntermediateShufflerItem* plain_intermediate_shuffler_item);

 private:
  // Loads a private EVP PKEY from a PEM-formatted string and returns it. It
  // aborts on error.
  EVP_PKEY* LoadPrivateKeyPEM(const std::string& key_pem);

  // Loads a public EVP PKEY from a DER-formatted string and returns it. It
  // aborts on error.
  EVP_PKEY* LoadPublicKeyDER(const uint8_t* key_bytes, size_t length);

  // Derives a shared secret symmetric key between a local private key and a
  // peer public key. Both asymmetric keys are in NIST P256, and the resulting
  // symmetric key has length |kSymmetricKeylength|. None of the arguments may
  // be nullptr, and |*secret_key| must have at least |kSymmetricKeyLength|
  // space allocated. Upon failure, the process aborts.
  void DeriveSecretSymmetricKey(EVP_PKEY* local_key, EVP_PKEY* peer_public_key,
                                uint8_t* secret_key);

  // My key
  EVP_PKEY* key_;

  // The ephemeral symmetric key for AES128-GCM encryption of
  // IntermediateShufflerItems
  sgx_aes_gcm_128bit_key_t intermediate_aesgcm_key_;
};

};  // namespace crypto
};  // namespace shuffler
};  // namespace prochlo

#endif  // __SGX_STASH_SHUFFLER_SHUFFLE_CRYPTER_H__
