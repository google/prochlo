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

#ifndef __SGX_STASH_SHUFFLER_STASH_SHUFFLER_H__
#define __SGX_STASH_SHUFFLER_STASH_SHUFFLER_H__

#include <cstddef>
#include <memory>
#include <vector>

#include "shuffle_crypter.h"
#include "shuffle_data.h"
#include "stash_stash.h"
#include "stash_window.h"

namespace prochlo {
namespace shuffler {
namespace stash {

// This class performs the distribution of input data into a partially shuffled
// intermediate array with some dummies interspersed. The CleanerUpper will
// compress the intermediate array into the fully-shuffled, compressed output
// data.
class BucketDistributor {
 public:
  BucketDistributor(size_t number_of_items, size_t number_of_buckets,
                    size_t chunk_size, size_t stash_size, size_t stash_chunks,
                    crypto::ShuffleCrypter* const crypter);

  // Distribute an array of encrypted items. |shuffler_items| may not be NULL,
  // and points to an array of items that is at least |number_of_items_|
  // elements long.
  //
  // Returns true on success and false otherwise, which means the whole shuffle
  // must fail as well.
  bool Distribute(const ShufflerItem* shuffler_items,
                  IntermediateShufflerItem* intermediate_array);

  // The (logical) running memory use of the BucketDistributor, in bytes. It
  // includes static size and heap use.
  size_t MemoryUse() const { return internal_size_; }

 private:
  // Read in a single bucket of encrypted items from the input, representing
  // input bucket |input_bucket|, split it into output chunks of intermediate
  // items (possibly leaving some in the internal stash), and write them out
  // into the external array of intermediate items.
  //
  // |bucket_start| cannot be NULL. It points to the first item in the
  // bucket. The array of input items must have at least |bucket_size|
  // consecutive items, starting with |*bucket_start|. |bucket_size| will
  // typically be the size of a typical bucket, although the last bucket of the
  // input array may be smaller; it may not be 0.
  //
  // Returns true on success, and false otherwise, which means the whole shuffle
  // must fail.
  bool DistributeBucket(size_t input_bucket, const ShufflerItem* bucket_start,
                        size_t bucket_size,
                        IntermediateShufflerItem* intermediate_array);

  // Empty the stash into the output, without consuming an input
  // bucket. |stash_bucket| is the index of chunk to be used for emptying stash
  // items (starting with 0). There is room for exactly |stash_chunks_| such
  // chunks in the intermediate array. So, in an intermediate array bucket, the
  // 0-th through (b-1)-st chunks belong to input buckets (if b is the number of
  // buckets), the b-th chunk belongs to the 0-th stash chunk, and so on. There
  // will be b+k chunks in each intermediate bucket, where k is |stash_chunks_|.
  bool ConsumeStash(size_t stash_bucket,
                    IntermediateShufflerItem* intermediate_array);

  // It fills the outbut buffer chunks from any pending items in the stash. Any
  // stash items used are copied into the output buffer chunks, and the stash is
  // updated to pop them.
  void FillChunksFromStash();

  // This assigns a random target output bucket to each item in an incoming
  // bucket.  Note that no actual items are moved around in memory during this
  // shuffle.
  void AssignBucketTargets(size_t bucket_size);

  // This method determines where an input item will be placed after
  // decryption. The choice is between a slot in the output buffer of
  // intermediate items, to be written out at the end of this bucket
  // distribution, or in one of the stash slots.
  //
  // Specifically, the location of the item in input bucket is looked up in the
  // results of the shuffle, where the target bucket is determined. If the
  // output chunk for that bucket is still not full, the next slot in that chunk
  // is returned. If the output chunk is full, a new slot is allocated to the
  // bucket in the stash and returned. If the stash is also full, nullptr is
  // returned.
  //
  // |input_bucket_index| must be within [0..max_bucket_size).
  PlainShufflerItem* FindPlainShufflerItemSlot(size_t input_bucket_index);

  // Reads in one bucket's worth of input items and decrypts them into either
  // the output buffer, or the stash.
  //
  // |bucket_start| cannot be NULL. It points to the first item in the
  // bucket. The array of input items must have at least |bucket_size|
  // consecutive items, starting with |*bucket_start|. |bucket_size| will
  // typically be the size of a typical bucket, although the last bucket of the
  // input array may be smaller; it may not be 0.
  //
  // Returns true on success and false if import has failed, which means the
  // whole shuffle failed.
  bool ImportBucket(const ShufflerItem* bucket_start, size_t bucket_size);

  // Resets the output buffer and fills it with dummy intermediate items.
  void ClearOutputBuffer();

  // Encrypts and exports the contents of the output buffer for the given input
  // bucket. |intermediate_array| may not be NULL, and should point to the
  // beginning of a buffer large enough to hold the entire intermediate array.
  void ExportOutput(size_t input_bucket,
                    IntermediateShufflerItem* intermediate_array);

  typedef std::vector<PlainIntermediateShufflerItem> Chunk;
  typedef std::vector<Chunk> OutputBuffer;
  typedef std::vector<size_t> OutputBufferSizes;
  typedef std::vector<size_t> InputBufferTargets;

  const size_t number_of_items_;
  const size_t number_of_buckets_;
  const size_t chunk_size_;
  const size_t stash_size_;
  const size_t stash_chunks_;  // The number of chunks we reserve for
                               // taking any left-over stash items at the
                               // end of the distribution phase.
  const size_t max_bucket_size_;
  const size_t intermediate_bucket_size_;
  Stash stash_;
  OutputBuffer output_;
  OutputBufferSizes output_sizes_;

  // We store in this array the destination bucket for each item in an incoming
  // bucket.
  InputBufferTargets input_buffer_targets_;

  size_t internal_size_;

  crypto::ShuffleCrypter* crypter_;
};

// The cleaner upper class contains all necessary state to perform the clean-up
// phase of the StashShuffler. It operates by scanning in sliding windows of
// |clean_up_window_| intermediate buckets, eliminating dummies, shuffling, and
// compressing into an output bucket at a time. The sliding window is filled up
// first, and then for every intermediate bucket read, one output bucket is
// written, until the end, when the remaining output buckets in the sliding
// window are written.
//
// Items are stored in an array of intermediate items, holding
// |clean_up_window_| intermediate buckets' worth. The array is organized as an
// in-place doubly-linked list, sharing the buffer with the free list.
//
// There are is also a queue of indices into the window, holding at most
// |clean_up_window_| buckets' worth of indices, in the order of output drainage
// (that is, after intermediate buckets have been shuffled).
//
// Output windows are written by reading items from this |drain_queue_|. The
// |window_| and the |drain_queue_| have exactly the same number of items.
class CleanerUpper {
 public:
  CleanerUpper(size_t number_of_items, size_t number_of_buckets,
               size_t chunk_size, size_t stash_chunks, size_t clean_up_window,
               crypto::ShuffleCrypter* crypter);

  // Cleans up an array of encrypted intermediate items and stores it in an
  // array of decrypted items. Neither |intermediate_array| nor
  // |analyzer_items| may be NULL. |intermediate_array| must point to a buffer
  // with enough room for |number_of_intermediate_items_| items, and
  // |analyzer_items| must point to a buffer with enough room for
  // |number_of_items_| items.
  bool CleanUp(const IntermediateShufflerItem* intermediate_array,
               AnalyzerItem* analyzer_items);

  // The (logical) running memory use of the CleanerUpper, in bytes. It includes
  // static size and heap use.
  size_t MemoryUse() const { return internal_size_; }

 private:
  typedef std::vector<size_t> ShuffleArray;
  typedef std::vector<size_t> DrainQueue;

  const size_t number_of_items_;
  const size_t number_of_buckets_;
  const size_t chunk_size_;
  const size_t stash_chunks_;     // The number of chunks we reserve for
                                  // taking any left-over stash items at the
                                  // end of the distribution phase.
  const size_t clean_up_window_;  // How many intermediate buckets' worth of
                                  // data do we buffer at any one time during
                                  // cleanup?

  const size_t max_bucket_size_;
  const size_t intermediate_bucket_size_;
  const size_t number_of_intermediate_items_;

  Window window_;

  // We use this array to hold and shuffle indices into |window_| for the
  // intermediate bucket being imported.
  ShuffleArray shuffle_array_;

  crypto::ShuffleCrypter* crypter_;

  // The drain queue holds window indices in the order they will be drained out
  // (i.e., as per the shuffle). It's maintained as a circular array. New
  // additions will be added at |drain_add_| and the next to be drained will be
  // at |drain_next_|. If |drain_add_| == |drain_next_|, then the queue is
  // empty. Note that the drain queue must have the exact number of items as the
  // window.
  DrainQueue drain_queue_;
  size_t drain_add_;
  size_t drain_next_;
  size_t internal_size_;

  // Imports an intermediate bucket. It reads each encrypted intermediate item
  // into internal memory. It decrypts the item into the Window, at a newly
  // allocated slot. If the item is a dummy, it is removed immediately from the
  // Window.
  //
  // It places window indices of the incoming items in a |shuffle_array_|, which
  // is shuffled after the entire bucket has been imported.
  //
  // Finally, it places window indices into the |drain_queue_| in the shuffled
  // order (for dummies, it just performs no-op updates of the queue).
  bool ImportIntermediateBucket(size_t intermediate_bucket,
                                const IntermediateShufflerItem* bucket_start,
                                size_t bucket_start_index);

  // Drains a single output bucket (the |output_bucket|-th output bucket) from
  // the current Window.
  bool DrainOutputBucket(size_t output_bucket, AnalyzerItem* bucket_start);
};

class StashShuffler {
 public:
  StashShuffler(std::unique_ptr<crypto::ShuffleCrypter> crypter);

  bool Shuffle(const ShufflerItem* const shuffler_items,
               const size_t number_of_items, const size_t number_of_buckets,
               const size_t chunk_size, const size_t stash_size,
               const size_t stash_chunks, const size_t clean_up_window,
               AnalyzerItem* const analyzer_items,
               IntermediateShufflerItem* const encrypted_intermediate_items,
               size_t number_of_intermediate_shuffler_items);

 private:
  std::unique_ptr<crypto::ShuffleCrypter> crypter_;
};

};  // namespace stash
};  // namespace shuffler
};  // namespace prochlo

#endif  // __SGX_STASH_SHUFFLER_STASH_SHUFFLER_H__
