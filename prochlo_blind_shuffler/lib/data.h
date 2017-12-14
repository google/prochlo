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

#ifndef __LIB_DATA_H__
#define __LIB_DATA_H__

namespace prochlo {

// Nomenclature for message structures:
//
// The client's encoder produces a Proclomation, i.e., an EncoderItem, which it
// wishes to deliver to the Analyzer, via the Shufflers. There is a Blinder
// Shuffler, which blinds the crowd-id and shuffles, and the Thresholder
// Shuffler, which decrypts the blinded crowd-id and shuffles again. The Blinder
// knows which item came from whom, but doesn't know the value of the crowd id
// for the item. The Thresholder finds out the actual (hashed) value of the
// crowd id for an item, but cannot link it to its source client.
//
// A BlinderItem travels from the Client to the Blinder.
//
// A ThresholderItem travels from the Blinder to the
// Thresholder.
//
// An AnalyzerItem travels from the Thresholder to the Analyzer.
//
// The Blinder stores the intermediate state of its shuffle on local
// (untrusted) storage, in the shape of an IntermediateBlinderItem.
// Similarly, the Thresholder stores its intermediate state in
// IntermediateThresholderItems.
//
// A Proclomation contains just the type of data (|metric|) and the value. The
// Client encrypts using AES128-GCM, with a key derived from its ephemeral key
// pair and the Analyzer's public key. That's the inner layer of the nested
// encryption, and constitutes the AnalyzerItem.
//
// Next, the Client constructs the middle layer of the nested encryption, by
// encrypting the AnalyzerItem again, using AES128-GCM, with a key derived from
// (another) ephemeral key pair, and the Thresholder's public key. That
// constitutes the ThresholderItem.
//
// Finally, the Client constructs the outer layer of the nested encryption, by
// adding the encrypted value of the crowd id to the ThresholderItem,
// and encrypting it, using AES128-GCM, with a key derived from (yet another)
// ephemeral key pair, and the Blinder's public key. That's the outer
// layer of the nested encryption, and constitutes the
// BlinderItem. This is what the Client transmits to the
// Blinder.
//
// Each of the shufflers performs the StashShuffle on its corresponding set of
// items, using local untrusted storage for its intermediate items: The
// Blinder receives BlinderItems, performs the StashShuffle on
// them, which stores intermediate state in IntermediateBlinderItems,
// and outputs shuffled items as an array of
// ThresholderItems. Similarly, the Thresholder performs the
// StashShuffle on its items, storing intermediate state in
// IntermediateThresholderItems, and outputting a shuffled array of
// AnalyzerItems.
//
// The StashShuffler shuffles the (appropriate) ShufflerItems in at least two
// rounds, storing intermediate results on local (but untrusted) storage. To
// ensure the shuffle is oblivious, the Shuffler decrypts ShufflerItems (as
// collected from the previous componenent, e.g., the Clients or the
// Blinder), and re-encrypts them unchanged using an ephemeral
// symmetric key of its choosing (again using AES128-GCM). The resulting
// structure is the corresponding Intermediate*ShufflerItem. In addition to the
// data encrypted in the next deeper nested layer of encryption, an
// Intermediate*ShufflerItem also contains some shuffler metadata (e.g., whether
// an Intermediate*ShufflerItem is a dummy).
//
// In a production setting, all of these message structures are represented by
// Protocol Buffers, which are not shown here.
//
// Note that we use struct sizes as the sizes of messages (i.e., sizeof(type)),
// rather than the number of bytes they'd take when marshalled. Due to
// alignment, the former may be larger than the latter.

// Default lengths
#define DATA_LENGTH 64
#define CROWD_ID_LENGTH 8

// Problem-specific lengths, in bytes.
constexpr size_t kProchlomationDataLength = DATA_LENGTH;
constexpr size_t kCrowdIdLength = CROWD_ID_LENGTH;

// Crypto-specific lengths.
constexpr size_t kPublicKeyLength = 91;  // This is the maximum length we devote
                                         // for storing a DER-encoded NIST
                                         // P-256 public key.
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

constexpr size_t kNonceLength = 12;  // The recommended nonce (i.e., IV) length
                                     // for AES128-GCM is 12 bytes.

constexpr size_t kTagLength = 16;  // The maximum tag length for AES128-GCM is
                                   // 16 bytes.

// General Nomenclature for nesting
//
// PlainItem -> contains the logical contents of the item for the Item
// recipient, in the clear. In some cases, this may just contain the Item of the
// downstream recipient, but we create a structure around it for clarity
//
// Item -> contains the encrypted Item, including the ciphertext, tag, nonce,
// and corresponding sender public key used to derive the shared secret for the
// AES-GCM encryption.


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

////////////////////////////////////////////////////////////////////////////////
// AnalyzerItem
////////////////////////////////////////////////////////////////////////////////
struct PlainAnalyzerItem {
  Prochlomation prochlomation;
};
constexpr size_t kPlainAnalyzerItemLength = sizeof(PlainAnalyzerItem);

struct AnalyzerItem {
  uint8_t ciphertext[kPlainAnalyzerItemLength];
  uint8_t tag[kTagLength];
  uint8_t nonce[kNonceLength];

  uint8_t client_public_key[kPublicKeyLength];
};
constexpr size_t kAnalyzerItemLength = sizeof(AnalyzerItem);

////////////////////////////////////////////////////////////////////////////////
// ThresholderItem
////////////////////////////////////////////////////////////////////////////////
// This is the item that the Thresholder handles, and it contains the
// AnalyzerItem. Note that after the Blinder has done the blinding, it will
// produce a slightly different ThresholderItem, containing a blinded encrypted
// crowd ID, as well as this ThresholderItem. This isn't shown here, since it's
// produced by the Blinder, not by the client, and therefore it's not in the
// purview of the generator.
struct PlainThresholderItem {
  AnalyzerItem analyzer_item;
};
constexpr size_t kPlainThresholderItemLength = sizeof(PlainThresholderItem);

struct ThresholderItem {
  uint8_t ciphertext[kPlainThresholderItemLength];
  uint8_t tag[kTagLength];
  uint8_t nonce[kNonceLength];

  uint8_t client_public_key[kPublicKeyLength];
};
constexpr size_t kThresholderItemLength = sizeof(ThresholderItem);


////////////////////////////////////////////////////////////////////////////////
// BlinderItem
////////////////////////////////////////////////////////////////////////////////
// This is the item that the Blinder handles, and it contains the
// ThresholderItem and the encrypted crowd ID.

constexpr size_t kP256PointLength = 33;
struct EncryptedBlindableCrowdId{
  // Public part. When blindable but not yet blinded, it starts out as Generator
  // ^ ClientPrivateKey. We also call this g^r in the code. When blinded, it
  // becomes Generator ^ (ClientPrivateKey * BlinderRandom), also called g^ra.
  uint8_t public_portion[kP256PointLength];

  // Secret part. When blindable but not yet blinded, it starts out as
  // (ThresholderPublicKey ^ ClientPrivateKey) * ECHashOfCrowdID. We also call
  // this h^r*m in the code. When blinded, it becomes ((ThresholderPublicKey ^
  // ClientPrivateKey) * ECHashOfCrowdID) ^ BlinderRandom, also called
  // (h^r*m)^a.
  uint8_t secret_portion[kP256PointLength];
};
constexpr size_t kEncryptedBlindableCrowdIdLength =
    sizeof(EncryptedBlindableCrowdId);

struct PlainBlinderItem {
  ThresholderItem thresholder_item;

  // The encrypted crowd ID for the Prochlomation included deep inside
  // |thresholder_item|.
  EncryptedBlindableCrowdId encoded_crowd_id;
};
constexpr size_t kPlainBlinderItemLength =
    sizeof(PlainBlinderItem);

struct BlinderItem {
  uint8_t ciphertext[kPlainBlinderItemLength];
  uint8_t tag[kTagLength];
  uint8_t nonce[kNonceLength];

  uint8_t client_public_key[kPublicKeyLength];
};
constexpr size_t kBlinderItemLength = sizeof(BlinderItem);

};  // namespace prochlo

#endif  //  __LIB_DATA_H__
