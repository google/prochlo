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

#ifndef __SGX_STASH_SHUFFLER_APPEND_ONLY_ALLOCATOR_H__
#define __SGX_STASH_SHUFFLER_APPEND_ONLY_ALLOCATOR_H__

#include <cstdint>

#include "Enclave.h"

namespace prochlo {

// The simple, allocate-only region allocator to be used for sharing memory
// between the two shuffle phases.
//
// This is aggressively thread-unfriendly. Not meant for multithreaded
// applications.
class AppendOnlyByteRegion {
 public:
  AppendOnlyByteRegion(size_t number_of_bytes);
  ~AppendOnlyByteRegion();
  uint8_t* Allocate(size_t bytes);
  void Reset();
  size_t Allocated() const;

 private:
  uint8_t* memory_;
  const size_t number_of_bytes_;
  size_t next_byte_;
};

template <typename T>
class AppendOnlyAllocator {
 public:
  typedef T value_type;
  typedef T& reference;

  AppendOnlyAllocator(AppendOnlyByteRegion* region);

  T* allocate(size_t n);

  void deallocate(T* pointer, size_t n);

 private:
  // The region itself
  AppendOnlyByteRegion* region_;
};

template <typename T>
AppendOnlyAllocator<T>::AppendOnlyAllocator(AppendOnlyByteRegion* region)
    : region_(region) {}

template <typename T>
T* AppendOnlyAllocator<T>::allocate(size_t n) {
  uint8_t* new_memory = region_->Allocate(sizeof(T) * n);
  return reinterpret_cast<T*>(new_memory);
}

template <typename T>
void AppendOnlyAllocator<T>::deallocate(T* pointer, size_t n) {
  // Do nothing. We'll deallocate the whole region
}


};  // prochlo

#endif  // __SGX_STASH_SHUFFLER_APPEND_ONLY_ALLOCATOR_H__
