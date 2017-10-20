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

#include "stash_window.h"

#include "append_only_allocator.h"
#include "stash_stash.h"

#include "Enclave.h"

namespace prochlo {
namespace shuffler {
namespace stash {

Window::Window(size_t size, AppendOnlyByteRegion* region)
    : uint8_allocator_(region),
      window_item_allocator_(region),
      is_allocated_(size, false, uint8_allocator_),
      window_items_(size, WindowItem(), window_item_allocator_),
      size_(size),
      free_(0),
      allocated_(size),
      allocated_size_(0) {
  CHECK_LT(0, size);  // Can't have a window of capacity 0.

  for (size_t i = 0; i < size; i++) {
    window_items_[i].next = i + 1;  // the size of the window is the 'bottom'
                                    // value, the equivalent of nullptr.
    window_items_[i].previous = i - 1;
  }
  window_items_[0].previous = size_;

  internal_size_ = sizeof(Window);
  internal_size_ += is_allocated_.size() * sizeof(uint8_t);
  internal_size_ += window_items_.size() * sizeof(WindowItem);  // window_items_
                                                                // contents.
  log_printf(LOG_INFO,
             "Created Window of size %lu"
             " elements, with internal size of %lu"
             " bytes (roughly).\n",
             size, internal_size_);
}

size_t Window::Allocate() {
  CHECK(!IsFull());

  // Take one from the front of the free list.
  size_t next_free = free_;
  free_ = window_items_[next_free].next;
  if (free_ != size_) {
    window_items_[free_].previous = size_;
  }

  // Push it into the front of the allocated list
  window_items_[next_free].next = allocated_;
  window_items_[next_free].previous = size_;
  if (allocated_ != size_) {
    window_items_[allocated_].previous = next_free;
  }
  allocated_ = next_free;

  is_allocated_[next_free] = true;

  allocated_size_++;

  return next_free;
}

size_t Window::Capacity() const { return size_; }

bool Window::IsFull() const { return free_ == size_; }

bool Window::IsEmpty() const { return allocated_ == size_; }

void Window::Remove(size_t index) {
  CHECK_GT(size_, index);
  CHECK_EQ(true, is_allocated_[index]);
  CHECK_EQ(false, IsEmpty());

  // Stich the allocated list together
  if (window_items_[index].previous != size_) {
    window_items_[window_items_[index].previous].next =
        window_items_[index].next;
  } else {
    allocated_ = window_items_[index].next;
  }
  if (window_items_[index].next != size_) {
    window_items_[window_items_[index].next].previous =
        window_items_[index].previous;
  }
  is_allocated_[index] = false;

  // Push into the front of the free list.
  window_items_[index].previous = size_;
  window_items_[index].next = free_;
  if (free_ != size_) {
    window_items_[free_].previous = index;
  }
  free_ = index;

  allocated_size_--;
}

size_t Window::AllocatedSize() const { return allocated_size_; }

PlainIntermediateShufflerItem& Window::operator[](size_t pos) {
  CHECK_GT(size_, pos);
  return window_items_[pos].intermediate_item;
}

};  // namespace stash
};  // namespace shuffler
};  // namespace prochlo
