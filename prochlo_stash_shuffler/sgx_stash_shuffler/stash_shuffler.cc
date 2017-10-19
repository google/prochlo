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

#include "stash_shuffler.h"
#include "shuffle_crypter.h"
#include "stash_stash.h"

#include "Enclave.h"
#include "Enclave_t.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <vector>
#include "sgx_trts.h"

namespace prochlo {
namespace shuffler {
namespace stash {

using crypto::ShuffleCrypter;

void BucketDistributor::ClearOutputBuffer() {
  for (OutputBuffer::iterator bucket = output_.begin(); bucket != output_.end();
       bucket++) {
    for (Chunk::iterator slot = bucket->begin(); slot != bucket->end();
         slot++) {
      slot->dummy = true;  // The rest of the content doesn't matter. The
                           // ciphertext will be unique.
    }
  }
  for (OutputBufferSizes::iterator chunk_size = output_sizes_.begin();
       chunk_size != output_sizes_.end(); chunk_size++) {
    *chunk_size = 0;
  }
}

PlainShufflerItem* BucketDistributor::FindPlainShufflerItemSlot(
    size_t input_bucket_index) {
  size_t target_bucket = input_buffer_targets_[input_bucket_index];
  size_t filled_chunk_size = output_sizes_[target_bucket];
  PlainShufflerItem* target_slot = nullptr;
  if (filled_chunk_size < chunk_size_) {
    log_printf(LOG_PEDANTIC,
               "Item %lu"
               " from this bucket will be imported straight into the output, "
               "in target bucket %lu"
               " and chunk slot %lu.\n",
               input_bucket_index, target_bucket, filled_chunk_size);
    PlainIntermediateShufflerItem& intermediate_item =
        output_[target_bucket][filled_chunk_size];
    intermediate_item.dummy = false;
    target_slot = &intermediate_item.plain_shuffler_item;
    output_sizes_[target_bucket]++;
  } else if (!stash_.IsFull()) {
    size_t allocated_slot_index = stash_.AllocateFront(target_bucket);
    log_printf(LOG_PEDANTIC,
               "Item %lu"
               " from this bucket will be imported into the stash for target "
               "bucket %lu"
               ", in stash slot %lu.\n",
               input_bucket_index, target_bucket, allocated_slot_index);
    target_slot = &stash_[allocated_slot_index];
  } else {
    log_printf(LOG_ERROR, "Import of item %lu",
               " from this bucket failed. The stash is full.\n",
               input_bucket_index);
  }
  return target_slot;
}

void BucketDistributor::FillChunksFromStash() {
  // This assumes that the output is entirely empty, and all items in there are
  // marked as dummies.

  for (size_t bucket = 0; bucket < number_of_buckets_; bucket++) {
    while (output_sizes_[bucket] < chunk_size_) {
      if (stash_.IsEmpty(bucket)) {
        break;
      }

      size_t stashed_item_index = stash_.Top(bucket);
      PlainShufflerItem& stashed_item = stash_[stashed_item_index];
      PlainIntermediateShufflerItem& intermediate_item =
          output_[bucket][output_sizes_[bucket]];
      intermediate_item.plain_shuffler_item = stashed_item;
      intermediate_item.dummy = false;
      stash_.Pop(bucket);
      output_sizes_[bucket]++;
    }
  }
}

bool BucketDistributor::ImportBucket(const ShufflerItem* bucket_start,
                                     size_t bucket_size) {
  CHECK_GE(max_bucket_size_, bucket_size);
  for (size_t i = 0; i < bucket_size; i++) {
    const ShufflerItem& shuffler_item_outside = bucket_start[i];
    // Copied inside first
    ShufflerItem shuffler_item(shuffler_item_outside);

    PlainShufflerItem* plain_shuffler_item = FindPlainShufflerItemSlot(i);
    if (plain_shuffler_item == nullptr) {
      log_printf(LOG_ERROR, "No decrypted item slot found.\n");
      return false;
    }

    CHECK(crypter_->DecryptShufflerItem(shuffler_item, plain_shuffler_item));
    // Show the crowd ID. If running on an input file from the generator, the
    // crowd IDs should increase by 3 mod 256 for successive ShufflerItems.
    //
    // printf("Imported plain shuffler item with crowd_id %d\n",
    //        plain_shuffler_item->crowd_id[0]);
  }
  return true;
}

void BucketDistributor::ExportOutput(
    size_t input_bucket, IntermediateShufflerItem* intermediate_array) {
  if (input_bucket < number_of_buckets_) {
    log_printf(LOG_WORDY, "Exporting output for input bucket %lu.\n",
               input_bucket);
  } else {
    log_printf(LOG_WORDY, "Exporting output for stash round %lu.\n",
               (input_bucket - number_of_buckets_));
  }
  size_t chunk_offset = input_bucket * chunk_size_;
  for (size_t output_bucket = 0; output_bucket < number_of_buckets_;
       output_bucket++) {
    size_t intermediate_bucket_start =
        output_bucket * intermediate_bucket_size_;
    size_t intermediate_chunk_start = intermediate_bucket_start + chunk_offset;
    IntermediateShufflerItem* chunk_array =
        &intermediate_array[intermediate_chunk_start];
    log_printf(LOG_PEDANTIC,
               "Chunk for output bucket %lu"
               " will go to the intermediate array at [%lu, %lu).\n",
               output_bucket, intermediate_chunk_start,
               intermediate_chunk_start + chunk_size_);
    for (size_t item_index = 0; item_index < chunk_size_; item_index++) {
      const PlainIntermediateShufflerItem& intermediate_item =
          output_[output_bucket][item_index];
      IntermediateShufflerItem encrypted_intermediate_item;

      CHECK(crypter_->EncryptIntermediateShufflerItem(
          intermediate_item, &encrypted_intermediate_item));

      log_printf(LOG_PEDANTIC,
                 "Chunk item %lu"
                 " to be written at is %s a dummy.\n",
                 item_index, &chunk_array[item_index],
                 (intermediate_item.dummy ? "" : "not "));
      chunk_array[item_index] = encrypted_intermediate_item;
    }
  }
}

void BucketDistributor::AssignBucketTargets(size_t bucket_size) {
  log_printf(LOG_WORDY, "Assigning targets to bucket of size %lu.\n",
             bucket_size);
  CHECK_LE(bucket_size, max_bucket_size_);

  // Now scan over the shuffled buffer and assign targets to input items.
  for (size_t index = 0; index < bucket_size; index++) {
    size_t target_bucket = ShuffleCrypter::RandomSizeT(number_of_buckets_);
    log_printf(LOG_PEDANTIC, "Sending item %d to bucket %d.\n", index,
               target_bucket);
    input_buffer_targets_[index] = target_bucket;
  }

  log_printf(LOG_WORDY, "Done with target assignment.\n");
}

bool BucketDistributor::DistributeBucket(
    size_t input_bucket, const ShufflerItem* bucket_start, size_t bucket_size,
    IntermediateShufflerItem* intermediate_array) {
  ClearOutputBuffer();
  FillChunksFromStash();
  AssignBucketTargets(bucket_size);
  if (!ImportBucket(bucket_start, bucket_size)) {
    log_printf(LOG_ERROR, "Couldn't import bucket %lu.\n", input_bucket);
    return false;
  }
  ExportOutput(input_bucket, intermediate_array);
  return true;
}

bool BucketDistributor::ConsumeStash(
    size_t stash_bucket, IntermediateShufflerItem* intermediate_array) {
  CHECK_GT(stash_chunks_, stash_bucket);
  ClearOutputBuffer();
  FillChunksFromStash();
  ExportOutput(number_of_buckets_ + stash_bucket, intermediate_array);

  return true;
}

constexpr size_t kReportingInterval = 10;

bool BucketDistributor::Distribute(
    const ShufflerItem* shuffler_items,
    IntermediateShufflerItem* intermediate_array) {
  for (size_t bucket = 0; bucket < number_of_buckets_; bucket++) {
    size_t bucket_start_index = bucket * max_bucket_size_;
    size_t bucket_size =
        std::min(max_bucket_size_, number_of_items_ - bucket_start_index);
    if (bucket % kReportingInterval == 0) {
      log_printf(LOG_INFO,
                 "Distributing input bucket %d in the range [%d, %d). "
                 "Current stash size is %d.\n",
                 bucket, bucket_start_index, (bucket_start_index + bucket_size),
                 stash_.Allocated());
      ocall_do_gettimeofday_start();
    }

    if (!DistributeBucket(bucket, &shuffler_items[bucket_start_index],
                          bucket_size, intermediate_array)) {
      log_printf(LOG_ERROR, "Couldn't distribute bucket %lu.\n", bucket);
      return false;
    }

    if (bucket % kReportingInterval == 0) {
      ocall_do_gettimeofday_end(bucket);
    }
  }

  for (size_t stash_round = 0; stash_round < stash_chunks_; stash_round++) {
    log_printf(LOG_INFO,
               "Draining stash, round %d. Current stash size is %d.\n",
               stash_round, stash_.Allocated());
    if (!ConsumeStash(stash_round, intermediate_array)) {
      log_printf(LOG_ERROR, "Couldn't drain the stash.\n");
      return false;
    }
  }

  if (!stash_.IsEmpty()) {
    log_printf(LOG_ERROR, "Stash is still not empty at the end (%lu).\n",
               stash_.Allocated());
    return false;  // Didn't drain enough
  }

  return true;
}

BucketDistributor::BucketDistributor(size_t number_of_items,
                                     size_t number_of_buckets,
                                     size_t chunk_size, size_t stash_size,
                                     size_t stash_chunks,
                                     crypto::ShuffleCrypter* crypter)
    : number_of_items_(number_of_items),
      number_of_buckets_(number_of_buckets),
      chunk_size_(chunk_size),
      stash_size_(stash_size),
      stash_chunks_(stash_chunks),
      max_bucket_size_(
          std::ceil((static_cast<float>(number_of_items) / number_of_buckets))),
      intermediate_bucket_size_((number_of_buckets_ + stash_chunks_) *
                                chunk_size_),
      stash_(stash_size_, number_of_buckets),
      output_(number_of_buckets_,
              Chunk(chunk_size_, PlainIntermediateShufflerItem())),
      output_sizes_(number_of_buckets_, 0),
      input_buffer_targets_(max_bucket_size_, number_of_buckets_),
      crypter_(crypter) {
  log_printf(LOG_INFO, "Created a BucketDistributor and it has size %d.\n",
             sizeof(BucketDistributor));
  size_t increment = sizeof(BucketDistributor);
  internal_size_ = increment;
  log_printf(LOG_INFO, "Inherent distributor size is %lu.\n", increment);

  increment = stash_.MemoryUse();
  internal_size_ += increment;

  printf(
      "Created bucket distributor for %lu"
      " items split into %lu"
      " buckets. The maximum bucket size is %lu"
      " and the required intermediate bucket size is %lu"
      " for a total of %lu"
      " external intermediate items. "
      "The stash has size %lu"
      ", chunks are %lu"
      " items each, and there are %lu"
      " chunks devoted to draining the stash. Stash drainage can deal "
      "with at most %lu"
      " stashed items.\n",
      number_of_items, number_of_buckets, max_bucket_size_,
      intermediate_bucket_size_, intermediate_bucket_size_ * number_of_buckets,
      stash_size_, chunk_size_, stash_chunks_,
      (chunk_size_ * stash_chunks_ * number_of_buckets_));

  increment =
      output_.size() *
      (sizeof(Chunk) +
       chunk_size_ * sizeof(PlainIntermediateShufflerItem));  // output_
                                                              // internal
                                                              // size
  internal_size_ += increment;
  log_printf(LOG_INFO, "Output buffer size is %lu.\n", increment);
  increment = output_sizes_.size() * sizeof(size_t);
  internal_size_ += increment;
  log_printf(LOG_INFO, "Output size array size is %lu.\n", increment);

  increment = input_buffer_targets_.size() * sizeof(size_t);
  internal_size_ += increment;
  printf(
      "Input buffer targets size is %lu. "
      "Total private memory use is %lu"
      " bytes.\n",
      increment, internal_size_);
}

CleanerUpper::CleanerUpper(size_t number_of_items, size_t number_of_buckets,
                           size_t chunk_size, size_t stash_chunks,
                           size_t clean_up_window,
                           crypto::ShuffleCrypter* crypter)
    : number_of_items_(number_of_items),
      number_of_buckets_(number_of_buckets),
      chunk_size_(chunk_size),
      stash_chunks_(stash_chunks),
      clean_up_window_(clean_up_window),
      max_bucket_size_(
          std::ceil((static_cast<float>(number_of_items) / number_of_buckets))),
      intermediate_bucket_size_((number_of_buckets_ + stash_chunks_) *
                                chunk_size_),
      number_of_intermediate_items_(intermediate_bucket_size_ *
                                    number_of_buckets_),
      window_(intermediate_bucket_size_ * clean_up_window_),
      shuffle_array_(intermediate_bucket_size_),
      crypter_(crypter),
      drain_queue_(intermediate_bucket_size_ * clean_up_window_,
                   number_of_intermediate_items_),
      drain_add_(0),
      drain_next_(0) {
  log_printf(LOG_INFO, "About to create a CleanerUpper\n");
  internal_size_ = sizeof(CleanerUpper);
  internal_size_ += window_.MemoryUse();
  internal_size_ += shuffle_array_.size() * sizeof(size_t);  // shuffle_array_
                                                             // contents
  internal_size_ += drain_queue_.size() * sizeof(size_t);    // drain_queue_
                                                             // contents
  log_printf(LOG_INFO,
             "Created the StashShuffler's CleanerUpper for %d"
             " items, split in %d buckets of maximum bucket size %d"
             " and intermediate bucket size of %d"
             ". Cleaning up a total of %d"
             " intermediate items, using a window of %d"
             " intermediate buckets. Total memory use is %d"
             " bytes roughly.\n",
             number_of_items, number_of_buckets, max_bucket_size_,
             intermediate_bucket_size_, number_of_intermediate_items_,
             clean_up_window_, internal_size_);
}

bool CleanerUpper::ImportIntermediateBucket(
    size_t intermediate_bucket, const IntermediateShufflerItem* bucket_start,
    size_t bucket_start_index) {
  if (intermediate_bucket % kReportingInterval == 0) {
    printf(
        "Importing intermediate bucket %d in the range [%d, %d). Window size "
        "is %d.\n",
        intermediate_bucket, bucket_start_index,
        bucket_start_index + intermediate_bucket_size_,
        window_.AllocatedSize());
    ocall_do_gettimeofday_start();
  }

  for (size_t intermediate_item_index = 0;
       intermediate_item_index < intermediate_bucket_size_;
       intermediate_item_index++) {
    IntermediateShufflerItem encrypted_item =
        bucket_start[intermediate_item_index];

    if (window_.IsFull()) {
      log_printf(LOG_ERROR, "The window is full.");
      return false;
    }
    size_t index_in_window = window_.Allocate();
    PlainIntermediateShufflerItem* intermediate_item =
        &window_[index_in_window];
    CHECK(crypter_->DecryptIntermediateShufflerItem(encrypted_item,
                                                    intermediate_item));
    if (intermediate_item->dummy) {
      window_.Remove(index_in_window);
      shuffle_array_[intermediate_item_index] = window_.Capacity();
    } else {
      shuffle_array_[intermediate_item_index] = index_in_window;
    }
  }

  crypter_->ShuffleIndexArray(&shuffle_array_, intermediate_bucket_size_);

  volatile size_t useless = 0;
  for (ShuffleArray::iterator index = shuffle_array_.begin();
       index != shuffle_array_.end(); index++) {
    if (*index == window_.Capacity()) {
      // This is a dummy item, write it but don't grow the queue.
      drain_queue_[drain_add_] = window_.Capacity();
      useless =
          drain_add_ + 1;  // TODO(maniatis): Will the optimizer remove this?
                           // Investigate
      drain_add_ = useless - 1;
      log_printf(LOG_PEDANTIC, "Next shuffled item is a dummy.\n");
    } else {
      log_printf(LOG_PEDANTIC,
                 "Next shuffled item is at window[%lu"
                 "], and placed in queue at %lu.\n",
                 *index, drain_add_);
      drain_queue_[drain_add_] = *index;
      useless = (drain_add_ + 1) % window_.Capacity();
      drain_add_ = useless;
    }
  }

  if (intermediate_bucket % kReportingInterval == 0) {
    ocall_do_gettimeofday_end(intermediate_bucket);
  }
  return true;
}

bool CleanerUpper::DrainOutputBucket(size_t output_bucket,
                                     AnalyzerItem* bucket_start) {
  size_t output_bucket_start_index = output_bucket * max_bucket_size_;
  size_t output_bucket_size =
      std::min(max_bucket_size_, number_of_items_ - output_bucket_start_index);

  if (output_bucket % kReportingInterval == 0) {
    log_printf(LOG_INFO,
               "Draining output bucket %d in the range [%d, %d). "
               "Window size is %d.\n",
               output_bucket, output_bucket_start_index,
               output_bucket_start_index + output_bucket_size,
               window_.AllocatedSize());
    ocall_do_gettimeofday_start();
  }

  for (size_t output_item = 0; output_item < output_bucket_size;
       output_item++) {
    if (window_.IsEmpty()) {
      log_printf(LOG_ERROR, "The window is empty.");
      return false;
    }

    // We're guaranteed to find an item in the drain queue.
    size_t window_index = drain_queue_[drain_next_];
    drain_next_ = (drain_next_ + 1) % window_.Capacity();
    bucket_start[output_item] =
        window_[window_index].plain_shuffler_item.analyzer_item;
    window_.Remove(window_index);
  }

  if (output_bucket % kReportingInterval == 0) {
    ocall_do_gettimeofday_end(output_bucket);
  }

  return true;
}

bool CleanerUpper::CleanUp(const IntermediateShufflerItem* intermediate_array,
                           AnalyzerItem* analyzer_items) {
  size_t window_size = std::min(clean_up_window_, number_of_buckets_);
  log_printf(LOG_INFO,
             "Cleanup Beginning. Proceeding in windows of size %lu.\n",
             window_size);

  // Fill up the window
  for (size_t intermediate_bucket = 0; intermediate_bucket < window_size;
       intermediate_bucket++) {
    size_t intermediate_bucket_start_index =
        intermediate_bucket * intermediate_bucket_size_;
    const IntermediateShufflerItem* intermediate_bucket_start =
        &intermediate_array[intermediate_bucket_start_index];
    if (!ImportIntermediateBucket(intermediate_bucket,
                                  intermediate_bucket_start,
                                  intermediate_bucket_start_index)) {
      log_printf(LOG_ERROR, "Couldn't import intermediate bucket %lu.\n",
                 intermediate_bucket);
      return false;
    }
  }

  // Steady state: drain one, fill one
  for (size_t intermediate_bucket = window_size;
       intermediate_bucket < number_of_buckets_; intermediate_bucket++) {
    size_t output_bucket = intermediate_bucket - window_size;

    size_t output_bucket_start_index = output_bucket * max_bucket_size_;
    AnalyzerItem* output_bucket_start =
        &analyzer_items[output_bucket_start_index];
    log_printf(LOG_WORDY,
               "Exporting output bucket %lu"
               " in the range [%lu, %lu).\n",
               output_bucket, output_bucket_start_index,
               output_bucket_start_index + max_bucket_size_);
    if (!DrainOutputBucket(output_bucket, output_bucket_start)) {
      log_printf(LOG_ERROR, "Couldn't drain output bucket %lu.\n",
                 output_bucket);
      return false;
    }

    size_t intermediate_bucket_start_index =
        intermediate_bucket * intermediate_bucket_size_;
    const IntermediateShufflerItem* intermediate_bucket_start =
        &intermediate_array[intermediate_bucket_start_index];
    if (!ImportIntermediateBucket(intermediate_bucket,
                                  intermediate_bucket_start,
                                  intermediate_bucket_start_index)) {
      log_printf(LOG_ERROR, "Couldn't import intermediate bucket %lu.\n",
                 intermediate_bucket);
      return false;
    }
  }

  // Drain the window
  for (size_t output_bucket = number_of_buckets_ - window_size;
       output_bucket < number_of_buckets_; output_bucket++) {
    size_t output_bucket_start_index = output_bucket * max_bucket_size_;
    AnalyzerItem* output_bucket_start =
        &analyzer_items[output_bucket_start_index];
    log_printf(LOG_WORDY,
               "Exporting output bucket %lu"
               " in the range [%lu, %lu"
               "), but may be smaller for the last bucket.\n",
               output_bucket, output_bucket_start_index,
               output_bucket_start_index + max_bucket_size_);
    if (!DrainOutputBucket(output_bucket, output_bucket_start)) {
      log_printf(LOG_ERROR, "Couldn't drain output bucket %lu.", output_bucket);
      return false;
    }
  }
  return true;
}

StashShuffler::StashShuffler(std::unique_ptr<ShuffleCrypter> crypter)
    : crypter_(std::move(crypter)) {
  log_printf(LOG_INFO, "Stash Shuffler size: %lu\n", sizeof(StashShuffler));
  log_printf(LOG_INFO, "Data have size: %lu\n", kProchlomationDataLength);
  log_printf(LOG_INFO, "Crowd IDs have size: %lu\n", kCrowdIdLength);
  log_printf(LOG_INFO, "IntermediateItems have size: %lu\n",
             sizeof(IntermediateShufflerItem));
  log_printf(LOG_INFO, "ShufflerItems have size: %lu\n", sizeof(ShufflerItem));
  log_printf(LOG_INFO, "AnalyzerItems have size: %lu\n",
             sizeof(PlainShufflerItem));
  log_printf(LOG_INFO, "IntermediateItems have size: %lu\n",
             sizeof(IntermediateShufflerItem));
}

bool StashShuffler::Shuffle(
    const ShufflerItem* const shuffler_items, const size_t number_of_items,
    const size_t number_of_buckets, const size_t chunk_size,
    const size_t stash_size, const size_t stash_chunks,
    const size_t clean_up_window, AnalyzerItem* const analyzer_items,
    IntermediateShufflerItem* const encrypted_intermediate_items,
    size_t number_of_intermediate_shuffler_items) {
  // Establish the buffers are outside
  if (sgx_is_outside_enclave(shuffler_items,
                             number_of_items * sizeof(ShufflerItem)) != 1) {
    log_printf(
        LOG_ERROR,
        "The buffer of shuffler items is not fully in untrusted memory.");
    return false;
  }
  if (sgx_is_outside_enclave(analyzer_items,
                             number_of_items * sizeof(AnalyzerItem)) != 1) {
    log_printf(
        LOG_ERROR,
        "The buffer of analyzer items is not fully in untrusted memory.");
    return false;
  }
  if (sgx_is_outside_enclave(encrypted_intermediate_items,
                             number_of_intermediate_shuffler_items *
                                 sizeof(IntermediateShufflerItem)) != 1) {
    log_printf(
        LOG_ERROR,
        "The buffer of encrypted intermediate shuffler items is not fully "
        "in untrusted memory.");
    return false;
  }

  {
    auto distributor =
        std::unique_ptr<stash::BucketDistributor>(new stash::BucketDistributor(
            number_of_items, number_of_buckets, chunk_size, stash_size,
            stash_chunks, crypter_.get()));
    log_printf(
        LOG_INFO,
        "Distributor was successfully constructed, so there is enough heap "
        "to proceed.\n");

    if (!distributor->Distribute(shuffler_items,
                                 encrypted_intermediate_items)) {
      log_printf(LOG_ERROR, "Couldn't distribute items.\n");
      return false;
    }
    log_printf(LOG_INFO, "Done distrubuting items\n");
  }
  {
    log_printf(LOG_INFO, "Beginning the clean up.\n");

    auto cleaner_upper = std::unique_ptr<stash::CleanerUpper>(
        new stash::CleanerUpper(number_of_items, number_of_buckets, chunk_size,
                                stash_chunks, clean_up_window, crypter_.get()));
    if (!cleaner_upper->CleanUp(encrypted_intermediate_items, analyzer_items)) {
      log_printf(LOG_ERROR, "Couldn't clean up intermediate items.\n");
      return false;
    }
  }

  return true;
}

};  // namespace stash
};  // namespace shuffler
};  // namespace prochlo
