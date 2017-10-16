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

#ifndef __SGX_STASH_SHUFFLER_STASH_STASH_H__
#define __SGX_STASH_SHUFFLER_STASH_STASH_H__

#include <cstddef>
#include <vector>

#include "shuffle_data.h"

namespace prochlo {
namespace shuffler {
namespace stash {

class StashItem {
 public:
  StashItem() {}
  PlainShufflerItem plain_shuffler_item;
  size_t next;
};

// The stash of items carried over across bucket distributor iterations. It
// consists of a fixed array of items in memory, which participate in either a
// free list or one of a number of stacks (organized as linked lists), one queue
// per target intermediate bucket.
//
// The size of the stash (a size_t value) is used as the nullptr.
class Stash {
 public:
  // Create the arena of stash items, all of which belong in the free list. The
  // stash will contain |size| items and |number_of_queues| queues.
  Stash(size_t size, size_t number_of_queues);

  // Allocate a stash item to bucket |bucket|. Returns the index of the newly
  // allocated item, and updates the stack and free list. The stash must not be
  // full.
  size_t AllocateFront(size_t bucket);

  // What's the stash capacity (i.e., its maximum size)?
  size_t Capacity() const;

  // Is the stash full?
  bool IsFull() const;

  // Is bucket |bucket| empty?
  bool IsEmpty(size_t bucket) const;

  // Is the stash completely empty?
  bool IsEmpty() const;

  // Return the top of bucket |bucket|. No other changes. The bucket must not be
  // empty.
  size_t Top(size_t bucket) const;

  // Pop the top of bucket |bucket|. Returns the index of the popped item, which
  // now belongs in the free list. The bucket must not be empty.
  size_t Pop(size_t bucket);

  // The number of currently allocated items.
  size_t Allocated() const;

  // Access the stashed element at the given position. This returns any item,
  // whether allocated or free.
  PlainShufflerItem& operator[](size_t pos);

  // The (logical) running memory use of the stash, in bytes. It includes static
  // size and heap use.
  size_t MemoryUse() const { return internal_size_; }

 private:
  std::vector<unsigned int> chunk_starts_;
  std::vector<StashItem> stash_items_;
  size_t size_;  // The number of items in the stash.
  size_t free_;  // The first item in the free list.
  size_t internal_size_;
  size_t allocated_;  // The number of allocated items.
};

};  // namespace stash
};  // namespace shuffler
};  // namespace prochlo

#endif  // __SGX_STASH_SHUFFLER_STASH_STASH_H__
