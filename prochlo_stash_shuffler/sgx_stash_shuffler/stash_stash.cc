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
#include <cmath>

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
      allocated_(0),
      internal_size_(sizeof(Stash) +  // intrinsic object size
                     // chunk_starts_
                     sizeof(chunk_starts_) +
                     chunk_starts_.size() * sizeof(unsigned int) +
                     // stash_items_
                     sizeof(stash_items_) +
                     stash_items_.size() * sizeof(StashItem) +
                     // primitives
                     sizeof(size_) +
                     sizeof(free_) +
                     sizeof(internal_size_) +
                     sizeof(allocated_)) {
  for (size_t i = 0; i < size; i++) {
    stash_items_[i].next = i + 1;  // the size of the stash is the 'bottom'
                                   // value, the equivalent of nullptr.
  }

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


size_t Stash::CalculateListSize(size_t start) const {
  size_t current = start;
  size_t list_size = 0;
  while (current != size_) {
    // Make sure the current pointer is valid
    CHECK_LE(0, current);
    CHECK_LE(current, size_);

    // Increment the count and proceed to the next item
    list_size++;
    current = stash_items_[current].next;
  }
  return list_size;
}

void Stash::PrintDiagnostics() const {
  size_t min = size_;
  size_t argmin = 0;
  size_t max = 0;
  size_t argmax = 0;
  const double mean = static_cast<double>(allocated_) / chunk_starts_.size();
  double sum_of_squared_deviations = 0;

  for (size_t index = 0; index < chunk_starts_.size(); index++) {
    size_t list_size = CalculateListSize(chunk_starts_[index]);

    if (list_size < min) {
      min = list_size;
      argmin = index;
    }
    if (list_size > max) {
      max = list_size;
      argmax = index;
    }

    size_t deviation = list_size - mean;
    double squared_deviation = deviation * deviation;
    sum_of_squared_deviations += squared_deviation;
  }
  double standard_deviation =
      std::sqrt(sum_of_squared_deviations / chunk_starts_.size());

  log_printf(LOG_INFO, "Stash statistics: %d/%d, %d@%d, %d@%d, %f, %f\n",
             allocated_, size_, min, argmin, max, argmax, mean, standard_deviation);
}

bool Stash::IsConsistent() const {
  size_t sum_of_list_sizes = 0;
  for (std::vector<unsigned int>::const_iterator start = chunk_starts_.begin();
       start != chunk_starts_.end(); start++) {
    size_t list_size = 0;
    size_t current = *start;
    while (current != size_) {
      // Make sure the current pointer is valid
      CHECK_LE(0, current);
      CHECK_LE(current, size_);

      // Increment the count and proceed to the next item
      list_size++;
      current = stash_items_[current].next;
    }
    sum_of_list_sizes += list_size;
  }
  if (sum_of_list_sizes != allocated_) {
    log_printf(
        LOG_ERROR,
        "The sum of the stash linked lists is %d and the number of "
        "allocated items is %d, but the two should be equal!\n",
        sum_of_list_sizes, allocated_);
    return false;
  }

  size_t free_size = 0;
  size_t current = free_;
  while (current != size_) {
    // Make sure the current pointer is valid
    CHECK_LE(0, current);
    CHECK_LE(current, size_);

    // Increment the count and proceed to the next item
    free_size++;
    current = stash_items_[current].next;
  }
  if (allocated_ + free_size != size_) {
    log_printf(
        LOG_ERROR,
        "The size of the free list is %d, but that is different from "
        "the difference between capacity and allocated size %d.\n",
        free_size, size_ - allocated_);
    return false;
  }
  return true;
}

};  // namespace stash
};  // namespace shuffler
};  // namespace prochlo
