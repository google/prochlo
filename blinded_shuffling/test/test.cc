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

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <memory>
#include <cstring>
#include <iostream>

#include <lib/crypto.h>
#include <lib/data.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

using prochlo::Crypto;

int main(int argc, char* argv[]) {
  uint8_t original_crowd_id[prochlo::kCrowdIdLength];
  uint8_t hashed_crowd_id[prochlo::kP256PointLength];
  uint8_t blinded_crowd_id[prochlo::kP256PointLength];

  uint8_t peer_key_pem[] = R"(
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKwzcNF9me2GvgbQ0Gkma1dvH+1VMdl+GyRpQiEJyUwEoAoGCCqGSM49
AwEHoUQDQgAEAAC5mzPTqU7LlLm+blHZYzGVcCB0CiibOs/LUl3vqOF4UtqUm8GG
eM2J71v8f6//ltZuvGq6GW70zK9F0wne+g==
-----END EC PRIVATE KEY-----
)";
  BIO* peer_key_bio;
  peer_key_bio = BIO_new_mem_buf(peer_key_pem, -1);
  EVP_PKEY* peer_key;
  peer_key = PEM_read_bio_PrivateKey(peer_key_bio, nullptr /* x= */,
                                     nullptr /* cb= */, nullptr /* u= */);
  if (peer_key == nullptr) {
    warn("Couldn't read in the public key.");
    exit(-1);
  }

  BIGNUM* one = BN_new();
  BN_one(one);
  prochlo::EncryptedBlindableCrowdId blindable;
  prochlo::EncryptedBlindableCrowdId blinded;

  for (int i = 0; i < 10; i++) {
    // Allocating this inside the loop, to ensure its innards are destroyed for
    // every iteration, in case there's a leak that should be exercised.
    Crypto crypto;

    std::cout << "Attempting a crowd ID with " << prochlo::kCrowdIdLength
              << " bytes of value " << i * 10 << "." << std::endl;
    memset(original_crowd_id, i * 10, prochlo::kCrowdIdLength);

    // This is just semi-intelligent initialization. The values aren't
    // important, but the idea is to have different values for the two
    // structures, and different values across attempts in the loop.
    memset(hashed_crowd_id, i * 10 + 1, prochlo::kP256PointLength);
    memset(blinded_crowd_id, i * 10 + 2, prochlo::kP256PointLength);

    if (!crypto.EncryptBlindableCrowdId(original_crowd_id, peer_key, &blindable,
                                        hashed_crowd_id)) {
      warn("Encryption failed.");
    } else {
      blinded = blindable;
      if (!crypto.BlindEncryptedBlindableCrowdId(&blinded, *one)) {
        warn("Blinding failed.");
      } else if (memcmp(blinded.public_portion, blindable.public_portion,
                        prochlo::kP256PointLength) != 0) {
        warn("The (fake) blinded public and the blindable public don't match!");
      } else if (memcmp(blinded.secret_portion, blindable.secret_portion,
                        prochlo::kP256PointLength) != 0) {
        warn("The (fake) blinded secret and the blindable secret don't match!");
      } else if (!crypto.DecryptBlindedCrowdId(
                     &blinded,
                     *EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(peer_key)),
                     blinded_crowd_id)) {
        warn("Decryption failed.");
      } else if (memcmp(hashed_crowd_id, blinded_crowd_id,
                        prochlo::kP256PointLength) != 0) {
        warn("The (fake) blinded crowd_id and the original hash don't match!");
      } else {
        std::cout << "Success! The (fake) blinded crowd_id and the original "
                     "hash match!"
                  << std::endl;
      }
    }
  }

  BN_free(one);
  BIO_free(peer_key_bio);
  EVP_PKEY_free(peer_key);
  return 0;
}
