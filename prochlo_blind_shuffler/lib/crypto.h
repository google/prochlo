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

#include <openssl/bn.h>
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

  // Similar to the other EncryptBlindableCrowdId function, but it takes an
  // explicit peer key, and also returns the (serialized) hash. This is
  // primarily meant for testing. In addition to the restrictions for the other
  // function, this also requires |peer_key| not to be NULL, the pointed-to key
  // to be a valid key pair in the same algorithm, and an initialized buffer
  // long enough to hold a serialized EC_POINT in |hash_buffer|.
  bool EncryptBlindableCrowdId(const uint8_t* crowd_id, EVP_PKEY* peer_key,
                               EncryptedBlindableCrowdId* encrypted_crowd_id,
                               uint8_t* hash_buffer);

  // Blind a the blindable encrypted crowd ID in |*encrypted_crowd_id|, using
  // the secret random number |alpha|. |encrypted_crowd_id| may not be NULL.
  bool BlindEncryptedBlindableCrowdId(
      EncryptedBlindableCrowdId* encrypted_crowd_id, const BIGNUM& alpha);

  // Decrypt the blinded crowd ID from |*encrypted_blinded_crowd_id| using the
  // private exponent |private_key| and store it in the buffer
  // |*blinded_crowd_id|. |blinded_crowd_id| cannot be NULL, and must point to
  // at least |kP256pointlength| bytes.
  bool DecryptBlindedCrowdId(
      EncryptedBlindableCrowdId* encrypted_blinded_crowd_id,
      const BIGNUM& private_key, uint8_t* blinded_crowd_id);

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

    // Write out the blindable state to
    // |*encrypted_crowd_id|. |encrypted_crowd_id| may not be NULL.
    bool SerializeBlindable(EncryptedBlindableCrowdId* encrypted_crowd_id);

    // Write out the blinded state to
    // |*encrypted_crowd_id|. |encrypted_crowd_id| may not be NULL.
    bool SerializeBlinded(EncryptedBlindableCrowdId* encrypted_crowd_id);

    // Serialize the given points to
    // |*encrypted_crowd_id|. |encrypted_crowd_id| may not be NULL.
    bool SerializeInternal(const EC_POINT& public_portion,
                           const EC_POINT& secret_portion,
                           EncryptedBlindableCrowdId* encrypted_crowd_id);

    // Serialize the decrypted blinded EC_POINT to the given buffer. |buffer|
    // may not be null point to a buffer of at least |kP256pointlength| bytes.
    bool SerializeDecrypted(uint8_t* buffer);

    // Serialize the EC hash to the given buffer. |buffer| may not be null point
    // to a buffer of at least |kP256pointlength| bytes.
    bool SerializeHash(uint8_t* buffer);

    // Read in state from the structure. Fails if either of the serialized
    // EC_POINTs are invalid.
    bool DeserializeBlindable(
        const EncryptedBlindableCrowdId& encrypted_crowd_id);

    // Read in state from the structure. Fails if either of the serialized
    // EC_POINTs are invalid.
    bool DeserializeBlinded(
        const EncryptedBlindableCrowdId& encrypted_crowd_id);

    // Read in state from the structure. Both provided pointers to EC_POINTs is
    // NULL.
    bool DeserializeInternal(
        const EncryptedBlindableCrowdId& encrypted_crowd_id,
        EC_POINT* public_portion, EC_POINT* secret_portion);

    // Blind the public and secret portions of blindable encryption with the
    // given exponent |alpha|. Blinding is done in place, updating
    // |public_point_| and |secret_point_|.
    bool Blind(const BIGNUM& alpha);

    // Decrypt the encrypted blindable state with the given |private_key|, and
    // store the result locally in |decrypted_blinded_point_|.
    bool Decrypt(const BIGNUM& private_key);

    // Reset the state for another computation. Primarily, this frees the
    // ephemeral key pair.
    void ResetEncryption();

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

    // Public portion, presumably a g^r
    EC_POINT* public_point_;

    // Secret portion, presumably a h^r*m
    EC_POINT* secret_point_;

    // Blinded public portion, presumably a g^ra
    EC_POINT* blinded_public_point_;

    // Blinded secret portion, presumably a h^ra*m
    EC_POINT* blinded_secret_point_;

    // g^rax
    EC_POINT* g_to_the_r_a_x_;

    // Decrypted blinded point, the proxy crowd ID on which the thresholder can
    // now threshold.
    EC_POINT* decrypted_blinded_point_;
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
