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

#ifndef __SGX_STASH_SHUFFLER_SHUFFLE_DATA_H__
#define __SGX_STASH_SHUFFLER_SHUFFLE_DATA_H__

#include <cstdint>

// Default lengths
#define DATA_LENGTH 64
#define CROWD_ID_LENGTH 8

namespace prochlo {
namespace shuffler {

constexpr size_t kProchlomationDataLength = DATA_LENGTH;
constexpr size_t kCrowdIdLength = CROWD_ID_LENGTH;

constexpr size_t kPublicKeyLength = 91;  // This is the maximum length we devote
                                         // for storing a DER-encoded NIST
                                         // P-256 public key.

constexpr size_t kTagLength = 16;  // The maximum tag length for AES128-GCM is
                                   // 16 bytes.

constexpr size_t kNonceLength = 12;
constexpr size_t kSharedSecretLength = 256 / 8;  // The length of the derived
                                                 // shared secret from Diffie
                                                 // Hellman key exchange on NIST
                                                 // P-256.
constexpr size_t kSymmetricKeyLength = 128 / 8;  // The length of an AES128 key.
constexpr size_t kSharedSecretExpansionLength = 256 / 8;  // The length of the
                                                          // pseudo-random space
                                                          // used to derive a
                                                          // shared symmetric
                                                          // key from a shared
                                                          // DH secret. It's
                                                          // determined by the
                                                          // length of SHA256.

////////////////////////////////////////////////////////////////////////////////
// Prochlomation
////////////////////////////////////////////////////////////////////////////////
// A prochlomation is the plain encoded data that a Client's Encoder generates
// and intends to deliver to an Analyzer.
struct Prochlomation {
  uint64_t metric;
  uint8_t data[kProchlomationDataLength];  // e.g., 64
};
constexpr size_t kProchlomationLength = sizeof(Prochlomation);  // e.g., 72
constexpr size_t kProchlomationCiphertextLength =
    kProchlomationLength;  // The ciphertext is the same length, but it is
                           // augmented by the MAC stored in |tag| below.

////////////////////////////////////////////////////////////////////////////////
// AnalyzerItem
////////////////////////////////////////////////////////////////////////////////
struct EncryptedProchlomation {
  // The result of encrypting a Prochlomation using AES128-GCM is |ciphertext|,
  // with MAC |tag|, starting with the IV in |nonce|.
  uint8_t ciphertext[kProchlomationCiphertextLength];
  uint8_t tag[kTagLength];
  uint8_t nonce[kNonceLength];

  // The key used to produce |ciphertext| is derived from the analyzer's key
  // pair and the client's ephermeral key pair. The public key of the client's
  // key pair is |client_public_key|.
  uint8_t client_public_key[kPublicKeyLength];
};
constexpr size_t kEncryptedProchlomationLength = sizeof(EncryptedProchlomation);

// We don't really care what an EncryptedProchlomation looks like inside. So,
// although exactly the same thing, an AnalyzerItem is just an opaque sequential
// laid out EncryptedProchlomation, without internal differentiation.
constexpr size_t kAnalyzerItemLength = kEncryptedProchlomationLength;
struct AnalyzerItem {
  uint8_t opaque[kEncryptedProchlomationLength];
};

////////////////////////////////////////////////////////////////////////////////
// ShufflerItem
////////////////////////////////////////////////////////////////////////////////
// This is the item that the Shuffler handles, and it contains the AnalyzerItem
// and the crowd ID.
class PlainShufflerItem {
 public:
  AnalyzerItem analyzer_item;
  uint8_t crowd_id[kCrowdIdLength];
  // Write this item out to the buffer pointed at by |plaintext|, not to exceed
  // |max_length|.
  size_t Write(uint8_t* plaintext, size_t max_length) const;
  // Replace the item with what's in the buffer
  size_t Read(const uint8_t* plaintext, size_t max_length);
};
constexpr size_t kPlainShufflerItemLength =
    kAnalyzerItemLength + kCrowdIdLength;

struct EncryptedPlainShufflerItem {
  // The result of encrypting an PlainShufflerItem using AES128-GCM is
  // |ciphertext|, with MAC |tag|, starting with the IV in |nonce|.
  uint8_t ciphertext[kPlainShufflerItemLength];
  uint8_t tag[kTagLength];
  uint8_t nonce[kNonceLength];

  // The key used to produce |ciphertext| is derived from the shuffler's key
  // pair and the client's ephermeral key pair. The public key of the client's
  // key pair is |client_public_key|. Note that the client may (in fact, might
  // as well) use two different ephemeral key pairs, one for the shuffler and
  // one for the analyzer. So this may not be the same as the
  // |client_public_key| in EncryptedProchlomation.
  uint8_t client_public_key[kPublicKeyLength];
};
constexpr size_t kEncryptedPlainShufflerItemLength =
    sizeof(EncryptedPlainShufflerItem);

// The ShufflerItem is just an EncryptedPlainShufflerItem
typedef EncryptedPlainShufflerItem ShufflerItem;
constexpr size_t kShufflerItemLength = kEncryptedPlainShufflerItemLength;

////////////////////////////////////////////////////////////////////////////////
// Internal Shuffler structures
////////////////////////////////////////////////////////////////////////////////

struct PlainIntermediateShufflerItem {
  // Real constructor
  PlainIntermediateShufflerItem(const PlainShufflerItem& plain_shuffler_item);

  // Dummy constructor
  PlainIntermediateShufflerItem();

  // Write this item out to the buffer pointed at by |plaintext|.
  size_t Write(uint8_t* plaintext, size_t max_length) const;
  // Replace the item with what's in the buffer
  void Read(const uint8_t* plaintext, size_t max_length);
  // Is this a dummy item?
  bool dummy;
  // The actual data item
  PlainShufflerItem plain_shuffler_item;
};

// The length of the PlainIntermediateShufflerItem when flattened out for
// encryption
constexpr size_t kIntermediateShufflerPlaintextSize =
    sizeof(uint8_t) +          // dummy
    kPlainShufflerItemLength;  // plain_shuffler_item

constexpr size_t kIntermediateShufflerCiphertextSize =
    kIntermediateShufflerPlaintextSize;

struct IntermediateShufflerItem {
  // The nonce used
  uint8_t nonce[kNonceLength];

  // And the sealed intermediate shuffler item. This is the result of
  // AEAD-sealing the PlainIntermediateShufflerItem <dummy, location, target,
  // generation, plain_shuffler_item>, using |nonce| as the nonce, with the
  // current shuffler symmetric key.
  uint8_t ciphertext[kIntermediateShufflerCiphertextSize];
  uint8_t tag[kTagLength];
};
constexpr size_t kIntermediateShufflerItemSize =
    sizeof(IntermediateShufflerItem);

};  // namespace shuffler
};  // namespace prochlo

#endif  // __SGX_STASH_SHUFFLER_SHUFFLE_DATA_H__
