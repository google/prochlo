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

#ifndef __SGX_STASH_SHUFFLER_STASH_WINDOW_H__
#define __SGX_STASH_SHUFFLER_STASH_WINDOW_H__

#include <cstddef>
#include <vector>

#include "shuffle_data.h"

namespace prochlo {
namespace shuffler {
namespace stash {

class WindowItem {
 public:
  WindowItem() : intermediate_item() {}
  PlainIntermediateShufflerItem intermediate_item;
  size_t next;
  size_t previous;
};

// The sliding window of intermediate items carried over across clean-up
// iterations. It consists of a fixed array of items in memory, which
// participate in either a free list or a doubly-linked list.
//
// The size of the window (a size_t value) is used as the nullptr.
class Window {
 public:
  // Create the arena of window items, all of which belong in the free list. The
  // window will contain |size| items.
  Window(size_t size);

  // Allocate a window item. Returns the index of the newly allocated item, and
  // updates the free list. The window must not be full.
  size_t Allocate();

  // Return the number of allocated items.
  size_t AllocatedSize() const;

  // What's the window capacity (i.e., its maximum size)?
  size_t Capacity() const;

  // Is the window full?
  bool IsFull() const;

  // Is the window completely empty?
  bool IsEmpty() const;

  // Remove item with index |index|. Move it into the free list. The item must
  // be allocated.
  void Remove(size_t index);

  // Access the window element at position |index|. This returns any item,
  // whether allocated or free, as long as it is inside the window.
  PlainIntermediateShufflerItem& operator[](size_t index);

  // The (logical) running memory use of the window, in bytes. It includes
  // static size and heap use.
  size_t MemoryUse() const { return internal_size_; }

 private:
  std::vector<bool> is_allocated_;
  std::vector<WindowItem> window_items_;
  size_t size_;       // The number of items in the stash.
  size_t free_;       // The first item in the free list.
  size_t allocated_;  // The first allocated item.
  size_t internal_size_;
  size_t allocated_size_;  // The number of allocated items.
};

};  // namespace stash
};  // namespace shuffler
};  // namespace prochlo

#endif  // __SGX_STASH_SHUFFLER_STASH_WINDOW_H__
