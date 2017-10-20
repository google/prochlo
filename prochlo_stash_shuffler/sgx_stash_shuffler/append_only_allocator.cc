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

#include <cstddef>
#include <cstdint>

#include "Enclave.h"
#include "append_only_allocator.h"

namespace prochlo {

AppendOnlyByteRegion::AppendOnlyByteRegion(size_t number_of_bytes)
    : memory_(new uint8_t[number_of_bytes]),
      number_of_bytes_(number_of_bytes),
      next_byte_(0) {}
AppendOnlyByteRegion::~AppendOnlyByteRegion() { delete[] memory_; }

uint8_t* AppendOnlyByteRegion::Allocate(size_t bytes) {
  CHECK_LE(next_byte_ + bytes, number_of_bytes_);
  uint8_t* result = &memory_[next_byte_];
  next_byte_ += bytes;
  return result;
}

void AppendOnlyByteRegion::Reset() { next_byte_ = 0; }

size_t AppendOnlyByteRegion::Allocated() const { return next_byte_; }

};  // prochlo
