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

#ifndef __SGX_STASH_SHUFFLER_ENCLAVE_H_
#define __SGX_STASH_SHUFFLER_ENCLAVE_H_

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define LOG_NOTHING 0
#define LOG_ERROR 1
#define LOG_WARNING 2
#define LOG_INFO 3
#define LOG_WORDY 4
#define LOG_PEDANTIC 5

#define LOG_LEVEL LOG_INFO

void printf(const char *fmt, ...);
void log_printf(const uint8_t level, const char *fmt, ...);

// Assertions
#define CHECK(i_)                                                        \
  {                                                                      \
    if (!(i_)) {                                                         \
      log_printf(LOG_ERROR, "Failed check (%s:%d): " #i_ "\n", __FILE__, \
                 __LINE__);                                              \
      abort();                                                           \
    }                                                                    \
  }
#define CHECK_GE(i_, j_) CHECK(i_ >= j_)
#define CHECK_EQ(i_, j_) CHECK(i_ == j_)
#define CHECK_GT(i_, j_) CHECK(i_ > j_)
#define CHECK_NE(i_, j_) CHECK(i_ != j_)
#define CHECK_LT(i_, j_) CHECK(i_ < j_)
#define CHECK_LE(i_, j_) CHECK(i_ <= j_)

#if defined(__cplusplus)
}
#endif

#endif // __SGX_STASH_SHUFFLER_ENCLAVE_H__
