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

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <memory>
#include <string>

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include "stash_shuffler.h"

void hexdump(const std::string& data) {
  const uint8_t* x = (uint8_t*)data.data();
  size_t len = data.size();

  printf("Dumping %lu bytes\n", len);

  while (len-- > 0) {
    printf("%.2x ", *x++);

    if ((len % 16) == 0) {
      printf("\n");
    }
  }

  printf("\n");
}

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char* fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_print_string(buf);
}

void log_printf(const uint8_t level, const char* fmt, ...) {
  if (level <= LOG_LEVEL) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
  }
}

std::string gPrivateKeyPem;

void ecall_set_key(const char* private_key_pem) {
  gPrivateKeyPem.assign(private_key_pem);
  log_printf(LOG_INFO, "Set the Shuffler private key to %s\n",
             gPrivateKeyPem.c_str());
  return;
}

void ecall_shuffle(void* shuffler_items, uint64_t number_of_items,
                   uint64_t number_of_buckets, uint64_t chunk_size,
                   uint64_t stash_size, uint64_t stash_chunks,
                   uint64_t clean_up_window, void* analyzer_items,
                   void* encrypted_intermediate_items,
                   uint64_t number_of_intermediate_shuffler_items) {
  if (gPrivateKeyPem.empty()) {
    // Oops, we have no private key.
    log_printf(LOG_ERROR, "No private key. Exiting.\n");
    return;
  }

  std::unique_ptr<prochlo::shuffler::crypto::ShuffleCrypter> crypter(
      new prochlo::shuffler::crypto::ShuffleCrypter(gPrivateKeyPem));
  prochlo::shuffler::stash::StashShuffler* stash_shuffler =
      new prochlo::shuffler::stash::StashShuffler(std::move(crypter));

  prochlo::shuffler::ShufflerItem* local_shuffler_items =
      (prochlo::shuffler::ShufflerItem*)shuffler_items;
  prochlo::shuffler::AnalyzerItem* local_analyzer_items =
      (prochlo::shuffler::AnalyzerItem*)analyzer_items;
  prochlo::shuffler::IntermediateShufflerItem*
      local_encrypted_intermediate_items =
          (prochlo::shuffler::IntermediateShufflerItem*)
              encrypted_intermediate_items;

  bool rc;

  log_printf(LOG_INFO,
             "Enclave.cc: Size check:\n"
             "sizeof(shuffler_items) = %lu\n"
             "sizeof(analyzer_items) = %lu\n"
             "sizeof(encrypted_intermediate_items) = %lu\n",
             sizeof(prochlo::shuffler::ShufflerItem),
             sizeof(prochlo::shuffler::AnalyzerItem),
             sizeof(prochlo::shuffler::IntermediateShufflerItem));

  rc = stash_shuffler->Shuffle(local_shuffler_items, (size_t)number_of_items,
                               (size_t)number_of_buckets, (size_t)chunk_size,
                               (size_t)stash_size, (size_t)stash_chunks,
                               (size_t)clean_up_window, local_analyzer_items,
                               local_encrypted_intermediate_items,
                               (size_t)number_of_intermediate_shuffler_items);

  log_printf(LOG_INFO, "Enclave result: %u\n", rc);

  delete stash_shuffler;

  return;
}

void ecall_distribute(void* shuffler_items, uint64_t number_of_items,
                      uint64_t number_of_buckets, uint64_t chunk_size,
                      uint64_t stash_size, uint64_t stash_chunks,
                      void* encrypted_intermediate_items, void* symmetric_key) {
  if (gPrivateKeyPem.empty()) {
    // Oops, we have no private key.
    log_printf(LOG_ERROR, "No private key. Exiting.\n");
    return;
  }

  std::unique_ptr<prochlo::shuffler::crypto::ShuffleCrypter> crypter(
      new prochlo::shuffler::crypto::ShuffleCrypter(
          gPrivateKeyPem, reinterpret_cast<uint8_t*>(symmetric_key)));
  std::unique_ptr<prochlo::shuffler::stash::BucketDistributor> distributor(
      new prochlo::shuffler::stash::BucketDistributor(
          number_of_items, number_of_buckets, chunk_size, stash_size,
          stash_chunks, crypter.get()));

  if (!distributor->Distribute(
          reinterpret_cast<prochlo::shuffler::ShufflerItem*>(shuffler_items),
          reinterpret_cast<prochlo::shuffler::IntermediateShufflerItem*>(
              encrypted_intermediate_items))) {
    log_printf(LOG_ERROR, "Bucket Distributor failed\n");
  } else {
    log_printf(LOG_INFO, "Bucket Distributor succeeded\n");
  }

  return;
}

void ecall_clean_up(uint64_t number_of_items, uint64_t number_of_buckets,
                    uint64_t chunk_size, uint64_t stash_chunks,
                    uint64_t clean_up_window, void* analyzer_items,
                    void* encrypted_intermediate_items, void* symmetric_key) {
  // Not really necessary, but still checking.
  if (gPrivateKeyPem.empty()) {
    // Oops, we have no private key.
    log_printf(LOG_ERROR, "No private key. Exiting.\n");
    return;
  }

  std::unique_ptr<prochlo::shuffler::crypto::ShuffleCrypter> crypter(
      new prochlo::shuffler::crypto::ShuffleCrypter(
          gPrivateKeyPem, reinterpret_cast<uint8_t*>(symmetric_key)));

  std::unique_ptr<prochlo::shuffler::stash::CleanerUpper> cleaner_upper(
      new prochlo::shuffler::stash::CleanerUpper(
          number_of_items, number_of_buckets, chunk_size, stash_chunks,
          clean_up_window, crypter.get()));

  if (!cleaner_upper->CleanUp(
          reinterpret_cast<prochlo::shuffler::IntermediateShufflerItem*>(
              encrypted_intermediate_items),
          reinterpret_cast<prochlo::shuffler::AnalyzerItem*>(analyzer_items))) {
    log_printf(LOG_ERROR, "Cleaner Upper failed\n");
  } else {
    log_printf(LOG_INFO, "Cleaner Upper succeeded\n");
  }

  return;
}
