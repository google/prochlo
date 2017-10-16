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

#include <cstring>

#include "shuffle_data.h"

#include "Enclave.h"

namespace prochlo {
namespace shuffler {

size_t PlainShufflerItem::Write(uint8_t* plaintext, size_t max_length) const {
  CHECK_GE(max_length, sizeof(PlainShufflerItem));

  size_t written_length = 0;

  AnalyzerItem* to_analyzer_item = reinterpret_cast<AnalyzerItem*>(plaintext);
  memcpy(to_analyzer_item, &analyzer_item, kAnalyzerItemLength);
  CHECK(kAnalyzerItemLength == sizeof(AnalyzerItem));
  written_length += sizeof(AnalyzerItem);
  plaintext += sizeof(AnalyzerItem);

  uint8_t* to_crowd_id = plaintext;
  memcpy(to_crowd_id, crowd_id, kCrowdIdLength);
  written_length += kCrowdIdLength;
  plaintext += kCrowdIdLength;

  return written_length;
}

size_t PlainShufflerItem::Read(const uint8_t* plaintext, size_t max_length) {
  CHECK_GE(max_length, sizeof(PlainShufflerItem));

  size_t read_length = 0;

  const AnalyzerItem* to_analyzer_item =
      reinterpret_cast<const AnalyzerItem*>(plaintext);
  memcpy(&analyzer_item, to_analyzer_item, kAnalyzerItemLength);
  CHECK(kAnalyzerItemLength == sizeof(AnalyzerItem));
  read_length += sizeof(AnalyzerItem);
  plaintext += sizeof(AnalyzerItem);

  const uint8_t* to_crowd_id = plaintext;
  memcpy(crowd_id, to_crowd_id, kCrowdIdLength);
  read_length += kCrowdIdLength;
  plaintext += kCrowdIdLength;

  return read_length;
}

PlainIntermediateShufflerItem::PlainIntermediateShufflerItem(
    const PlainShufflerItem& plain_shuffler_item)
    : dummy(false), plain_shuffler_item(plain_shuffler_item) {}

PlainIntermediateShufflerItem::PlainIntermediateShufflerItem() : dummy(true) {}

size_t PlainIntermediateShufflerItem::Write(uint8_t* plaintext,
                                            size_t max_length) const {
  CHECK_GE(max_length, kIntermediateShufflerPlaintextSize);
  int length = 0;

  uint8_t* to_dummy = reinterpret_cast<uint8_t*>(plaintext);
  *to_dummy = dummy ? 1 : 0;
  length += sizeof(uint8_t);
  plaintext += sizeof(uint8_t);

  if (dummy) {
    // Again, the purpose of this is to avoid encrypting an uninitialized
    // |plain_shuffler_item|
    std::memset(plaintext, 0, sizeof(plain_shuffler_item));
  } else {
    plain_shuffler_item.Write(plaintext, max_length - length);
  }
  length += sizeof(plain_shuffler_item);
  plaintext += sizeof(plain_shuffler_item);
  CHECK_EQ(length, kIntermediateShufflerPlaintextSize);
  return length;
}

void PlainIntermediateShufflerItem::Read(const uint8_t* plaintext,
                                         size_t max_length) {
  CHECK_GE(max_length, kIntermediateShufflerPlaintextSize);
  // Fill in the plain shuffler item. Read first the dummy, location, target,
  // generation, and then the encoder item.
  size_t read_length = 0;
  uint8_t dummy_int = *(reinterpret_cast<const uint8_t*>(plaintext));
  CHECK((dummy_int == 0) || (dummy_int == 1));
  dummy = dummy_int == 1;
  plaintext += sizeof(uint8_t);
  read_length += sizeof(uint8_t);

  size_t remaining_bytes = max_length - read_length;
  size_t read_bytes = plain_shuffler_item.Read(plaintext, remaining_bytes);
  CHECK_EQ(remaining_bytes, read_bytes);
}

};  // namespace shuffler
};  // namespace prochlo
