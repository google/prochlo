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

#ifndef __LIB_CRYPTO_H__
#define __LIB_CRYPTO_H__

#include <memory>

#include <openssl/evp.h>
#include <openssl/ec.h>

#include "lib/data.h"

namespace prochlo {

class Crypto {
 public:
  // Load the public key for the Analyzer
  bool load_analyzer_key(const std::string& keyfile);

  // Load the public key for the Blinder
  bool load_blinder_key(const std::string& keyfile);

  // Load the public key for the Thresholder
  bool load_thresholder_key(const std::string& keyfile);

  Crypto();
  ~Crypto();

  bool EncryptForAnalyzer(const PlainAnalyzerItem& plain_analyzer_item,
                          AnalyzerItem* analyzer_item);

  bool EncryptForBlinder(const PlainBlinderItem& plain_blinder_item,
                         BlinderItem* blinder_item);

  bool EncryptForThresholder(const PlainThresholderItem& plain_thresholder_item,
                             ThresholderItem* thresholder_item);

  // Create a blindable encrypted encoding of |*crowd_id|, and place it in
  // |*encrypted_crowd_id|. Neither |crowd_id| nor |encrypted_crowd_id| may be
  // NULL. |*crowd_id| must have room for at least |kCrowdIdLength|
  // bytes. Returns true on success and false otherwise.
  bool EncryptBlindableCrowdId(const uint8_t* crowd_id,
                               EncryptedBlindableCrowdId* encrypted_crowd_id);

 private:
  // A convenient interface for encrypting between pairs of Prochlo messages
  // without producing a separate serialized copy of the input.
  class Encryption {
   public:
    Encryption(EVP_PKEY* peer_key) : peer_key(peer_key) {}

    EVP_PKEY* ToPeerKey() { return peer_key; }

    virtual bool StreamDataForEncryption(EVP_CIPHER_CTX* ctx) = 0;
    virtual uint8_t* ToPublicKey() = 0;
    virtual uint8_t* ToNonce() = 0;
    virtual uint8_t* ToTag() = 0;
    virtual const char* TypeString() = 0;

    EVP_PKEY* peer_key;
  };

  class PlainAnalyzerItemToAnalyzerItemEncryption : public Crypto::Encryption {
   public:
    PlainAnalyzerItemToAnalyzerItemEncryption(
        EVP_PKEY* peer_key, const PlainAnalyzerItem& plain_analyzer_item,
        AnalyzerItem* analyzer_item);
    const PlainAnalyzerItem& plain_analyzer_item;
    AnalyzerItem* analyzer_item;

    uint8_t* ToPublicKey() override;
    const char* TypeString() override;
    uint8_t* ToNonce() override;
    uint8_t* ToTag() override;
    bool StreamDataForEncryption(EVP_CIPHER_CTX* ctx) override;
  };

  class PlainThresholderItemToThresholderItemEncryption : public Crypto::Encryption {
   public:
    PlainThresholderItemToThresholderItemEncryption(
        EVP_PKEY* peer_key, const PlainThresholderItem& plain_thresholder_item,
        ThresholderItem* thresholder_item);
    const PlainThresholderItem& plain_thresholder_item;
    ThresholderItem* thresholder_item;

    uint8_t* ToPublicKey() override;
    const char* TypeString() override;
    uint8_t* ToNonce() override;
    uint8_t* ToTag() override;
    bool StreamDataForEncryption(EVP_CIPHER_CTX* ctx) override;
  };

  class PlainBlinderItemToBlinderItemEncryption : public Crypto::Encryption {
   public:
    PlainBlinderItemToBlinderItemEncryption(
        EVP_PKEY* peer_key, const PlainBlinderItem& plain_blinder_item,
        BlinderItem* blinder_item);
    const PlainBlinderItem& plain_blinder_item;
    BlinderItem* blinder_item;

    uint8_t* ToPublicKey() override;
    const char* TypeString() override;
    uint8_t* ToNonce() override;
    uint8_t* ToTag() override;
    bool StreamDataForEncryption(EVP_CIPHER_CTX* ctx) override;
  };

  // The context for constructing blindable encryptions of a message (typically
  // a sensitive crowd ID).
  class BlindableEncryption {
   public:
    BlindableEncryption(Crypto* crypto);
    ~BlindableEncryption();

    // Produce a NIST P-256 point that is a cryptographic hash of |*data|.
    // |data| may not be null, and must be allocated and holding at least
    // |data_length| bytes. Return true on success and false on failure. On
    // success, p256_point_
    // will hold the found hash point. Note that this is not a thread-safe
    // function, since it uses global state without synchronization.
    bool HashToCurve(const uint8_t* data, size_t data_length);

    // Compute the blindable encryption of the EC point in
    // |p256_point_hash_|. This generates an ephemeral EC key pair and uses it
    // to encrypt the hash point to the thresholder's public key.
    //
    // The particular computation is as follows, given the thresholder's public
    // key h and hash m.
    //
    // - Generate an ephemeral keypair (g^r, r) for some random r and generator
    // g.
    //
    // - Compute h^r * m
    //
    // - Return (g^r, h^r * m) as the encryption.
    //
    // g is a generator of the NIST P256 curve. m is in |p256_point_hash_|. g^r
    // is stored in |p256_point_g_r_|. h^r*m is stored in |p256_point_h_r_m_|.
    //
    // All EC_POINT structures must have been initialized a not NULL.
    bool EncryptBlindable(EVP_PKEY* peer_key);

    // Write out the state to |*encrypted_crowd_id|. |encrypted_crowd_id| may
    // not be NULL.
    bool Serialize(EncryptedBlindableCrowdId* encrypted_crowd_id);

    // Reset the state for another computation. Primarily, this frees the
    // ephemeral key pair.
    void Reset();

    // My containing crypto class.
    Crypto* crypto_;

    // The NIST P256 curve.
    EC_GROUP* p256_;

    // The hash on the P256 curve of a message.
    EC_POINT* hash_;

    // The X coordinate of the hash point |p256_point_hash_|;
    BIGNUM* x_coordinate_;

    // My ephemeral public key, serialized.
    EVP_PKEY* my_ephemeral_key_;

    // h^r
    EC_POINT* h_to_the_r_;

    // h^r * m
    EC_POINT* h_to_the_r_times_m_;
  };

  bool MakeEncryptedMessage(Encryption* encryption);

  // If |binary_key| is not NULL, write out a serialized version of the key.
  bool GenerateKeyPair(EVP_PKEY* peer_public_key, EVP_PKEY** key_out,
                       uint8_t* binary_key);

  bool DeriveSecretSymmetricKey(EVP_PKEY* local_key, EVP_PKEY* peer_public_key,
                                uint8_t* secret_key);
  bool Encrypt(const uint8_t* symmetric_key, Encryption* encryption);

  // Load a public key returning the structure
  EVP_PKEY* load_public_key(const std::string& keyfile);

  EVP_PKEY* public_blinder_key_;
  EVP_PKEY* public_thresholder_key_;
  EVP_PKEY* public_analyzer_key_;

  // The context for blindable encryption.
  BlindableEncryption blindable_encryption_;
};

}  // namespace prochlo

#endif  // __LIB_CRYPTO_H__
