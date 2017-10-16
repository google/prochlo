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

#include "stash_stash.h"
#include "Enclave.h"

namespace prochlo {
namespace shuffler {
namespace stash {

Stash::Stash(size_t size, size_t number_of_queues)
    : chunk_starts_(number_of_queues, size),  // All queues will start with
                                              // |size|, which is our nullptr
                                              // equivalent.
      stash_items_(size),
      size_(size),
      free_(0),
      allocated_(0) {
  CHECK_LT(0, size);  // Can't have a stash of capacity 0.

  for (size_t i = 0; i < size; i++) {
    stash_items_[i].next = i + 1;  // the size of the stash is the 'bottom'
                                   // value, the equivalent of nullptr.
  }

  internal_size_ = sizeof(Stash);
  internal_size_ += chunk_starts_.size() * sizeof(int);       // chunk_starts_
                                                              // contents
  internal_size_ += stash_items_.size() * sizeof(StashItem);  // stash_items_
                                                              // contents
  log_printf(
      LOG_INFO,
      "Created a stash of size %d elements, split across %d queues, with "
      "internal size of %d bytes, roughly.\n",
      size, number_of_queues, internal_size_);
}

size_t Stash::Capacity() const { return size_; }

bool Stash::IsFull() const { return free_ == size_; }

bool Stash::IsEmpty(size_t bucket) const {
  CHECK_GT(chunk_starts_.size(), bucket);

  return chunk_starts_[bucket] == size_;
}

bool Stash::IsEmpty() const {
  // Horrible hack. Maintaining a count of free or allocated items would be
  // faster.
  for (std::vector<unsigned int>::const_iterator start = chunk_starts_.begin();
       start != chunk_starts_.end(); start++) {
    if (*start != size_) {
      return false;
    }
  }
  return true;
}

size_t Stash::AllocateFront(size_t bucket) {
  CHECK(!IsFull());
  CHECK_GT(chunk_starts_.size(), bucket);

  // Take one out of the free list.
  size_t next_free = free_;
  free_ = stash_items_[next_free].next;

  // Push it into the target bucket
  stash_items_[next_free].next = chunk_starts_[bucket];
  chunk_starts_[bucket] = next_free;

  allocated_++;

  return next_free;
}

size_t Stash::Top(size_t bucket) const {
  CHECK_GT(chunk_starts_.size(), bucket);
  CHECK_EQ(false, IsEmpty(bucket));

  return chunk_starts_[bucket];
}

size_t Stash::Pop(size_t bucket) {
  CHECK_GT(chunk_starts_.size(), bucket);
  CHECK_EQ(false, IsEmpty(bucket));

  // Take pop off the top
  size_t top = chunk_starts_[bucket];
  chunk_starts_[bucket] = stash_items_[top].next;

  // Push it down the free list
  stash_items_[top].next = free_;
  free_ = top;

  allocated_--;

  return top;
}

size_t Stash::Allocated() const { return allocated_; }

PlainShufflerItem& Stash::operator[](size_t pos) {
  CHECK_GT(size_, pos);
  return stash_items_[pos].plain_shuffler_item;
}

};  // namespace stash
};  // namespace shuffler
};  // namespace prochlo
