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

#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <string>

#include <lib/prochlo.h>

namespace prochlo {

bool Crypto::load_analyzer_key(const std::string& keyfile) {
  public_analyzer_key_ = load_public_key(keyfile);
  return public_analyzer_key_ != nullptr;
}

bool Crypto::load_blinder_key(const std::string& keyfile) {
  public_blinder_key_ = load_public_key(keyfile);
  return public_blinder_key_ != nullptr;
}

bool Crypto::load_thresholder_key(const std::string& keyfile) {
  public_thresholder_key_ = load_public_key(keyfile);
  return public_thresholder_key_ != nullptr;
}

EVP_PKEY* Crypto::load_public_key(const std::string& keyfile) {
  FILE* fp = fopen(keyfile.c_str(), "r");
  if (fp == nullptr) {
    warn("fopen()");
    return nullptr;
  }

  EVP_PKEY* key;
  key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
  fclose(fp);

  if (key == nullptr) {
    ERR_print_errors_fp(stderr);
  }
  return key;
}

Crypto::Crypto()
    : public_blinder_key_(nullptr),
      public_thresholder_key_(nullptr),
      public_analyzer_key_(nullptr),
      blindable_encryption_(this) {
  // Pedantically check that we have the same endianness everywhere
  uint32_t number = 1;
  assert(reinterpret_cast<uint8_t*>(&number)[0] == 1);

  // Ensure the AES128-GCM default nonce length is kNonceLength
  assert(EVP_CIPHER_iv_length(EVP_aes_128_gcm()) == kNonceLength);
}

Crypto::~Crypto() {
  if (public_blinder_key_ != nullptr) {
    EVP_PKEY_free(public_blinder_key_);
  }
  if (public_thresholder_key_ != nullptr) {
    EVP_PKEY_free(public_thresholder_key_);
  }
  if (public_analyzer_key_ != nullptr) {
    EVP_PKEY_free(public_analyzer_key_);
  }
}

Crypto::PlainAnalyzerItemToAnalyzerItemEncryption::
    PlainAnalyzerItemToAnalyzerItemEncryption(
        EVP_PKEY* peer_key, const PlainAnalyzerItem& plain_analyzer_item,
        AnalyzerItem* analyzer_item)
    : Encryption(peer_key),
      plain_analyzer_item(plain_analyzer_item),
      analyzer_item(analyzer_item) {}

uint8_t* Crypto::PlainAnalyzerItemToAnalyzerItemEncryption::ToPublicKey() {
  return analyzer_item->client_public_key;
}

const char* Crypto::PlainAnalyzerItemToAnalyzerItemEncryption::TypeString() {
  return "Prochlomation->AnalyzerItem";
}

uint8_t* Crypto::PlainAnalyzerItemToAnalyzerItemEncryption::ToNonce() {
  return analyzer_item->nonce;
}

uint8_t* Crypto::PlainAnalyzerItemToAnalyzerItemEncryption::ToTag() {
  return analyzer_item->tag;
}

bool Crypto::PlainAnalyzerItemToAnalyzerItemEncryption::StreamDataForEncryption(
    EVP_CIPHER_CTX* ctx) {
  // Stream the plain analyzer item to the cipher and write out the ciphertext.
  uint8_t* next_byte = nullptr;
  size_t ciphertext_byte_count = 0;
  int32_t out_length;

  // First the metric
  next_byte = &analyzer_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_metric = reinterpret_cast<const uint8_t*>(
      &plain_analyzer_item.prochlomation.metric);
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length, to_metric,
                        sizeof(plain_analyzer_item.prochlomation.metric)) !=
      1) {
    warn("Couldn't encrypt metric with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;

  // And the data
  next_byte = &analyzer_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_data = plain_analyzer_item.prochlomation.data;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length, to_data,
                        kProchlomationDataLength) != 1) {
    warn("Couldn't encrypt data with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;
  assert(ciphertext_byte_count == kPlainAnalyzerItemLength);
  return true;
}

Crypto::PlainBlinderItemToBlinderItemEncryption::
    PlainBlinderItemToBlinderItemEncryption(
        EVP_PKEY* peer_key, const PlainBlinderItem& plain_blinder_item,
        BlinderItem* blinder_item)
    : Encryption(peer_key),
      plain_blinder_item(plain_blinder_item),
      blinder_item(blinder_item) {}

uint8_t* Crypto::PlainBlinderItemToBlinderItemEncryption::ToPublicKey() {
  return blinder_item->client_public_key;
}

const char* Crypto::PlainBlinderItemToBlinderItemEncryption::TypeString() {
  return "PlainBlinderItem->BlinderItem";
}

uint8_t* Crypto::PlainBlinderItemToBlinderItemEncryption::ToNonce() {
  return blinder_item->nonce;
}

uint8_t* Crypto::PlainBlinderItemToBlinderItemEncryption::ToTag() {
  return blinder_item->tag;
}

bool Crypto::PlainBlinderItemToBlinderItemEncryption::StreamDataForEncryption(
    EVP_CIPHER_CTX* ctx) {
  // Stream the PlainBlinderItem to the CIPHER and write out the ciphertext.
  uint8_t* next_byte = nullptr;
  size_t ciphertext_byte_count = 0;
  int32_t out_length;

  // First the thresholder item (i.e., its innards).
  next_byte = &blinder_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_thresholder_item_ciphertext =
      plain_blinder_item.thresholder_item.ciphertext;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length,
                        to_thresholder_item_ciphertext,
                        kPlainThresholderItemLength) != 1) {
    warn("Couldn't encrypt thresholder item ciphertext with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;

  next_byte = &blinder_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_thresholder_item_tag =
      plain_blinder_item.thresholder_item.tag;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length, to_thresholder_item_tag,
                        kTagLength) != 1) {
    warn("Couldn't encrypt thresholder item tag with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;

  next_byte = &blinder_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_thresholder_item_nonce =
      plain_blinder_item.thresholder_item.nonce;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length, to_thresholder_item_nonce,
                        kNonceLength) != 1) {
    warn("Couldn't encrypt thresholder item nonce with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;

  next_byte = &blinder_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_thresholder_item_client_public_key =
      plain_blinder_item.thresholder_item.client_public_key;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length,
                        to_thresholder_item_client_public_key,
                        kPublicKeyLength) != 1) {
    warn(
        "Couldn't encrypt thresholder item client public key with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;

  // And now finish with the encoded crowd ID
  next_byte = &blinder_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_encoded_crowd_id_g_to_the_r =
      plain_blinder_item.encoded_crowd_id.g_to_the_r;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length, to_encoded_crowd_id_g_to_the_r,
                        kP256PointLength) != 1) {
    warn("Couldn't encrypt encoded crowd ID public part with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;
  next_byte = &blinder_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_encoded_crowd_id_h_to_the_r_times_m =
      plain_blinder_item.encoded_crowd_id.h_to_the_r_times_m;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length,
                        to_encoded_crowd_id_h_to_the_r_times_m,
                        kP256PointLength) != 1) {
    warn("Couldn't encrypt encoded crowd ID valud part with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;

  assert(ciphertext_byte_count == kPlainBlinderItemLength);
  return true;
}

Crypto::PlainThresholderItemToThresholderItemEncryption::
    PlainThresholderItemToThresholderItemEncryption(
        EVP_PKEY* peer_key, const PlainThresholderItem& plain_thresholder_item,
        ThresholderItem* thresholder_item)
    : Encryption(peer_key),
      plain_thresholder_item(plain_thresholder_item),
      thresholder_item(thresholder_item) {}

uint8_t* Crypto::PlainThresholderItemToThresholderItemEncryption::ToPublicKey() {
  return thresholder_item->client_public_key;
}

const char* Crypto::PlainThresholderItemToThresholderItemEncryption::TypeString() {
  return "PlainThresholderItem->ThresholderItem";
}

uint8_t* Crypto::PlainThresholderItemToThresholderItemEncryption::ToNonce() {
  return thresholder_item->nonce;
}

uint8_t* Crypto::PlainThresholderItemToThresholderItemEncryption::ToTag() {
  return thresholder_item->tag;
}

bool Crypto::PlainThresholderItemToThresholderItemEncryption::
    StreamDataForEncryption(EVP_CIPHER_CTX* ctx) {
  // Stream the PlainThresholderItem to the CIPHER and write out the ciphertext.
  uint8_t* next_byte = nullptr;
  size_t ciphertext_byte_count = 0;
  int32_t out_length;

  // First the analyzer item (i.e., its innards). Note that AnalyzerItem ==
  // PlainThresholderItem == EncryptedProchlomation
  next_byte = &thresholder_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_analyzer_item_ciphertext =
      plain_thresholder_item.analyzer_item.ciphertext;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length,
                        to_analyzer_item_ciphertext,
                        kPlainAnalyzerItemLength) != 1) {
    warn("Couldn't encrypt analyzer item ciphertext with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;

  next_byte = &thresholder_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_analyzer_item_tag =
      plain_thresholder_item.analyzer_item.tag;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length, to_analyzer_item_tag,
                        kTagLength) != 1) {
    warn("Couldn't encrypt analyzer item tag with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;

  next_byte = &thresholder_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_analyzer_item_nonce =
      plain_thresholder_item.analyzer_item.nonce;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length, to_analyzer_item_nonce,
                        kNonceLength) != 1) {
    warn("Couldn't encrypt analyzer item nonce with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;

  next_byte = &thresholder_item->ciphertext[ciphertext_byte_count];
  const uint8_t* to_analyzer_item_client_public_key =
      plain_thresholder_item.analyzer_item.client_public_key;
  if (EVP_EncryptUpdate(ctx, next_byte, &out_length,
                        to_analyzer_item_client_public_key,
                        kPublicKeyLength) != 1) {
    warn(
        "Couldn't encrypt analyzer item client public key with AES128-GCM.");
    ERR_print_errors_fp(stderr);
    return false;
  }
  ciphertext_byte_count += out_length;

  assert(ciphertext_byte_count == kPlainThresholderItemLength);
  return true;
}


bool Crypto::MakeEncryptedMessage(Encryption* encryption) {
  EVP_PKEY* my_key = nullptr;
  EVP_PKEY* peer_key = encryption->ToPeerKey();

  do {  // Using BoringSSL's scoped EVP_PKEY pointers would be a lot more
        // exciting here that the do {} while(false) kludge.
    if (!GenerateKeyPair(peer_key, &my_key, encryption->ToPublicKey())) {
      warn("Couldn't generate an ephemeral keypair during %s message creation.",
           encryption->TypeString());
      break;
    }

    uint8_t symmetric_key[kSymmetricKeyLength];
    if (!DeriveSecretSymmetricKey(my_key, peer_key, symmetric_key)) {
      warn("Couldn't generate a symmetric key during %s message creation.",
           encryption->TypeString());
      break;
    }

    if (!Encrypt(symmetric_key, encryption)) {
      warn("Couldn't encrypt for %s.", encryption->TypeString());
      break;
    }

    if (my_key != nullptr) {
      EVP_PKEY_free(my_key);
    }
    return true;
  } while (false);

  if (my_key != nullptr) {
    EVP_PKEY_free(my_key);
  }
  return false;
}

bool Crypto::EncryptForAnalyzer(const PlainAnalyzerItem& plain_analyzer_item,
                                AnalyzerItem* analyzer_item) {
  PlainAnalyzerItemToAnalyzerItemEncryption encryption(
      public_analyzer_key_, plain_analyzer_item, analyzer_item);
  return MakeEncryptedMessage(&encryption);
}

bool Crypto::EncryptForBlinder(const PlainBlinderItem& plain_blinder_item,
                               BlinderItem* blinder_item) {
  PlainBlinderItemToBlinderItemEncryption encryption(
      public_blinder_key_, plain_blinder_item, blinder_item);
  return MakeEncryptedMessage(&encryption);
}

bool Crypto::EncryptForThresholder(
    const PlainThresholderItem& plain_thresholder_item,
    ThresholderItem* thresholder_item) {
  PlainThresholderItemToThresholderItemEncryption encryption(
      public_thresholder_key_, plain_thresholder_item, thresholder_item);
  return MakeEncryptedMessage(&encryption);
}

bool Crypto::EncryptBlindableCrowdId(
    const uint8_t* crowd_id, EncryptedBlindableCrowdId* encrypted_crowd_id) {
  // Hash the crowd ID on the curve
  if (!blindable_encryption_.HashToCurve(crowd_id, kCrowdIdLength)) {
    warn("Failed to hash crowd ID to P256 curve.");
    return false;
  }

  // Encrypt the hashed crowd ID
  if (!blindable_encryption_.EncryptBlindable(public_thresholder_key_)) {
    warn("Failed to encrypt hashed crowd ID.");
    return false;
  }

  // Serialize the crowd ID to the supplied structure.
  if (!blindable_encryption_.Serialize(encrypted_crowd_id)) {
    warn("Failed to serialize encrypted blindable crowd ID.");
    return false;
  }

  // And reset the state of the context
  blindable_encryption_.Reset();

  return true;
}

bool Crypto::GenerateKeyPair(EVP_PKEY* peer_public_key,
                             EVP_PKEY** key_out, uint8_t* binary_key) {
  assert(peer_public_key != nullptr);
  assert(key_out != nullptr);
  assert(*key_out == nullptr);

  EVP_PKEY_CTX* ctx = nullptr;
  EVP_PKEY* key = nullptr;
  BIO* bio = NULL;

  do {
    // Generate a key based on the peer's key parameters.
    ctx = EVP_PKEY_CTX_new(peer_public_key, /*e=*/nullptr);
    if (ctx == nullptr) {
      warn("Couldn't create an EVP_PKEY_CTX.");
      ERR_print_errors_fp(stderr);
      break;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
      warn("Couldn't initialize the key-pair generation.");
      ERR_print_errors_fp(stderr);
      break;
    }

    if (EVP_PKEY_keygen(ctx, &key) != 1) {
      warn("Couldn't generate a key pair.");
      ERR_print_errors_fp(stderr);
      break;
    }

    // Serialize the key.
    bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
      warn("Couldn't allocate an OpenSSL buffer.");
      ERR_print_errors_fp(stderr);
      break;
    }

    if (i2d_PUBKEY_bio(bio, key) != 1) {
      warn("Couldn't serialize a key pair.");
      ERR_print_errors_fp(stderr);
      break;
    }

    uint8_t* serialized_buffer = nullptr;
    size_t serialized_key_length = BIO_get_mem_data(bio, &serialized_buffer);
    // We'd better have provisioned enough space for the serialized public key.
    assert(serialized_key_length <= kPublicKeyLength);

    // Now write the results out. Only write the serialized key if a buffer was
    // supplied.
    if (binary_key != nullptr) {
      memcpy(binary_key, serialized_buffer, serialized_key_length);
    }
    *key_out = key;

    // Successful return.
    EVP_PKEY_CTX_free(ctx);
    BIO_free(bio);
    return true;
  } while (false);

  // Unsuccessful return.
  *key_out = nullptr;
  if (key != nullptr) {
    EVP_PKEY_free(key);
  }
  if (ctx != nullptr) {
    EVP_PKEY_CTX_free(ctx);
  }
  if (bio != nullptr) {
    BIO_free(bio);
  }
  return false;
}

bool Crypto::DeriveSecretSymmetricKey(EVP_PKEY* local_key,
                                      EVP_PKEY* peer_public_key,
                                      uint8_t* secret_key) {
  assert(local_key != nullptr);
  assert(peer_public_key != nullptr);
  assert(secret_key != nullptr);

  EVP_PKEY_CTX* ctx = nullptr;

  do {
    ctx = EVP_PKEY_CTX_new(local_key, /*e=*/nullptr);
    if (ctx == nullptr) {
      warn("Couldn't create an EVP_PKEY_CTX for secret derivation.");
      ERR_print_errors_fp(stderr);
      break;
    }

    if (EVP_PKEY_derive_init(ctx) != 1) {
      warn("Couldn't initiate a secret derivation.");
      ERR_print_errors_fp(stderr);
      break;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_public_key) != 1) {
      warn("Couldn't set the public key of my peer for a secret derivation.");
      ERR_print_errors_fp(stderr);
      break;
    }

    size_t derived_secret_length = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &derived_secret_length) != 1) {
      warn("Couldn't find the length of the derived secret.");
      ERR_print_errors_fp(stderr);
      break;
    }
    assert(derived_secret_length <= kSharedSecretLength);
    uint8_t derived_secret[kSharedSecretLength];

    if (EVP_PKEY_derive(ctx, derived_secret, &derived_secret_length) != 1) {
      warn("Couldn't derive a shared secret.");
      ERR_print_errors_fp(stderr);
      break;
    }

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
    if (hmac == nullptr) {
      warn("Couldn't HMAC the derived secret.");
      ERR_print_errors_fp(stderr);
      break;
    }
    assert(hmac_length == kSharedSecretExpansionLength);
    // Now HMAC the previous HMAC result with itself as a key, and some
    // well-defined additional data (namely, 1).
    uint8_t one = 1;
    hmac = HMAC(EVP_sha256(),
                /* key = */ expansion, kSharedSecretExpansionLength,
                /* d = */ &one, sizeof(one),  // arbitrary choice
                /* md = */ expansion, /* md_len= */ nullptr);  // No need to
                                                               // obtain the
                                                               // length of the
                                                               // md yet again.
    if (hmac == nullptr) {
      warn("Couldn't HMAC to expand the symmetric key.");
      ERR_print_errors_fp(stderr);
      break;
    }
    // Now we have good key material in |expansion|. Strip it down to the
    // keysize of AES128.
    assert(kSharedSecretExpansionLength > kSymmetricKeyLength);
    memcpy(secret_key, expansion, kSymmetricKeyLength);

    EVP_PKEY_CTX_free(ctx);
    return true;
  } while (false);

  if (ctx != nullptr) {
    EVP_PKEY_CTX_free(ctx);
  }
  return false;
}

bool Crypto::Encrypt(const uint8_t* symmetric_key, Encryption* encryption) {
  assert(encryption != nullptr);

  EVP_CIPHER_CTX* ctx = nullptr;
  do {
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
      warn("Couldn't create a new EVP_CIPHER_CTX.");
      ERR_print_errors_fp(stderr);
      break;
    }

    EVP_CIPHER_CTX_init(ctx);

    // Set up a random nonce
    if (RAND_bytes(encryption->ToNonce(), kNonceLength) != 1) {
      warn("Couldn't generate random nonce.");
      ERR_print_errors_fp(stderr);
      break;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(),
                           /* impl= */ nullptr, symmetric_key,
                           /* iv= */ encryption->ToNonce()) != 1) {
      warn("Couldn't initialize for AES128-GCM encryption.");
      ERR_print_errors_fp(stderr);
      break;
    }

    if (!encryption->StreamDataForEncryption(ctx)) {
      warn("Couldn't stream data for %s AES128-GCM encryption.",
           encryption->TypeString());
      break;
    }

    // Now finalize to obtain the tag. We should have no pending ciphertext data
    // at this point.
    int32_t out_length;
    if (EVP_EncryptFinal_ex(ctx, /* out= */ nullptr, &out_length) != 1) {
      warn("Couldn't finalize the prochlomation encryption.");
      ERR_print_errors_fp(stderr);
      break;
    }
    assert(out_length == 0);

    // We have filled in the ciphertext. Now we also need to fill in the tag.
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLength,
                            encryption->ToTag()) != 1) {
      warn("Couldn't obtain the AEAD tag from the prochlomation encryption.");
      ERR_print_errors_fp(stderr);
      break;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
  } while (false);

  if (ctx != nullptr) {
    EVP_CIPHER_CTX_free(ctx);
  }
  return false;
}

// The maximum number of times we're willing to try a different hash as a point
// on the P256 curve.
constexpr int kMaxHashToCurveSalt = 256;
constexpr size_t kHashLength = 256/8;  // SHA256 has 256 bits.

bool Crypto::BlindableEncryption::HashToCurve(const uint8_t* data,
                                              size_t data_length) {
  assert(p256_ != nullptr);
  assert(hash_ != nullptr);
  assert(x_coordinate_ != nullptr);
  assert(data != nullptr);

  uint8_t hash[kHashLength];
  unsigned int hash_length;

  for (int salt = 0; salt < kMaxHashToCurveSalt; salt++) {
    // Produce a new candidate point
    // 1. Hash the data
    if (HMAC(EVP_sha256(), /* key= */ &salt, /* key_len= */ sizeof(salt),
             data, data_length, hash, &hash_length) == nullptr) {
      warn("Couldn't HMAC the crowd ID.");
      return false;
    }
    assert(hash_length == kHashLength);

    // 2. Turn the bytes into a BIGNUM
    if (BN_bin2bn(hash, hash_length, x_coordinate_) == nullptr) {
      warn("Couldn't turn the HMAC'ed crowd ID into a BIGNUM.");
      return false;
    }

    for (int y_bit = 0; y_bit <= 1; y_bit++) {
      // 3. Turn the BIGNUM into the xcoordinate of the point
      if (EC_POINT_set_compressed_coordinates_GFp(
              p256_, hash_, x_coordinate_, y_bit, nullptr /* bn_ctx= */) != 1) {
        // Invalid point. Kick it out.
        continue;
      }

      // 4. Check if the point is on the curve.  This is probably redundant,
      // since ..._set_compressed_coordinates_... only returns success for a
      // valid point on the curve.
      int is_on_curve_result =
          EC_POINT_is_on_curve(p256_, hash_, nullptr /* bn_ctx= */);
      if (is_on_curve_result == -1) {
        warn("The curve check for the crowd ID EC_POINT failed.");
        return false;
      }
      if (is_on_curve_result == 1) {
        return true;
      }
      warn("Valid compressed coordinates are not on curve.");
    }
  }

  // We failed to find a point.
  warn("Failed to find a hash of the crowd ID that is actually on the curve.");
  return false;
}

bool Crypto::BlindableEncryption::EncryptBlindable(EVP_PKEY* peer_key) {
  // There shouldn't be an ephemeral key in the context
  assert(my_ephemeral_key_ == nullptr);

  // Returns (g^r, r) in |my_ephemeral_key|.
  if (!crypto_->GenerateKeyPair(peer_key, &my_ephemeral_key_,
                                nullptr /* serialization buffer */)) {
    warn("Couldn't generate an ephemeral keypair during blindable encryption.");
    return false;
  }

  // Compute h^r
  if (EC_POINT_mul(p256_,        // curve
                   h_to_the_r_,  // output
                   nullptr,      // no g^ component
                   EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(peer_key)),  // h
                   EC_KEY_get0_private_key(
                       EVP_PKEY_get0_EC_KEY(my_ephemeral_key_)),  // r
                   nullptr /* bn_ctx= */) != 1) {
    EVP_PKEY_free(my_ephemeral_key_);
    my_ephemeral_key_ = nullptr;
    return false;
  }

  // Compute h^r*m
  if (EC_POINT_add(p256_,
                   h_to_the_r_times_m_,  // output
                   h_to_the_r_, hash_, nullptr /* bn_ctx= */) != 1) {
    EVP_PKEY_free(my_ephemeral_key_);
    my_ephemeral_key_ = nullptr;
    return false;
  }

  // Now my_ephemeral_key_ holds g^r (in its public key portion) and
  // h_to_the_r_times_m_ holds h^r*m.
  return true;
}

bool Crypto::BlindableEncryption::Serialize(
    EncryptedBlindableCrowdId* encrypted_crowd_id) {
  assert(my_ephemeral_key_ != nullptr);
  assert(h_to_the_r_times_m_ != nullptr);

  unsigned int required_length = EC_POINT_point2oct(
      p256_, h_to_the_r_times_m_, POINT_CONVERSION_COMPRESSED,
      nullptr /* out buffer */, kP256PointLength, nullptr /* bn_ctx= */);
  if (required_length > kP256PointLength) {
    return false;
  }
  if (EC_POINT_point2oct(
      p256_, h_to_the_r_times_m_, POINT_CONVERSION_COMPRESSED,
      encrypted_crowd_id->h_to_the_r_times_m, kP256PointLength,
      nullptr /* bn_ctx= */) == 0) {
    return false;
  }

  required_length = EC_POINT_point2oct(
      p256_, EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(my_ephemeral_key_)),
      POINT_CONVERSION_COMPRESSED, nullptr /* out buffer */, kP256PointLength,
      nullptr /* bn_ctx= */);
  if (required_length > kP256PointLength) {
    return false;
  }
  if (EC_POINT_point2oct(
          p256_,
          EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(my_ephemeral_key_)),
          POINT_CONVERSION_COMPRESSED, encrypted_crowd_id->g_to_the_r,
          kP256PointLength, nullptr /* bn_ctx= */) == 0) {
    return false;
  }

  return true;
}

Crypto::BlindableEncryption::BlindableEncryption(Crypto* crypto)
    : crypto_(crypto),
      p256_(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)),
      hash_(EC_POINT_new(p256_)),
      x_coordinate_(BN_new()),
      my_ephemeral_key_(nullptr),
      h_to_the_r_(EC_POINT_new(p256_)),
      h_to_the_r_times_m_(EC_POINT_new(p256_)) {
  assert(crypto_ != nullptr);
  assert(p256_ != nullptr);
  assert(hash_ != nullptr);
  assert(x_coordinate_ != nullptr);
  assert(h_to_the_r_ != nullptr);
  assert(h_to_the_r_times_m_ != nullptr);
}

Crypto::BlindableEncryption::~BlindableEncryption() {
  if (p256_ != nullptr) {
    EC_GROUP_free(p256_);
  }
  if (hash_ != nullptr) {
    EC_POINT_free(hash_);
  }
  if (x_coordinate_ != nullptr) {
    BN_free(x_coordinate_);
  }
  if (my_ephemeral_key_ != nullptr) {
    EVP_PKEY_free(my_ephemeral_key_);
  }
  if (h_to_the_r_ != nullptr) {
    EC_POINT_free(h_to_the_r_);
  }
  if (h_to_the_r_times_m_ != nullptr) {
    EC_POINT_free(h_to_the_r_times_m_);
  }
}

void Crypto::BlindableEncryption::Reset() {
  if (my_ephemeral_key_ != nullptr) {
    EVP_PKEY_free(my_ephemeral_key_);
    my_ephemeral_key_ = nullptr;
  }
}

}  // namespace prochlo
