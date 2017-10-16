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

#ifndef __LIB_PROCHLO_H__
#define __LIB_PROCHLO_H__

#include <memory>

#include <lib/crypto.h>
#include <lib/data.h>

namespace prochlo {

enum {
  METRIC_STRING_TEST = 0x1,
};

constexpr size_t kGenerationReportingInterval = 10000;

// Common configuration of the Prochlo executables
struct Configuration {
  static const char* const USAGE;
  int parse_args(int argc, char* argv[]);

  // The pathname to the output file where the generated ShufflerItems will be
  // written.
  std::string output_file;

  // The pathname to the shuffler key.
  std::string shuffler_key_file;

  // The pathname to the analyzer key.
  std::string analyzer_key_file;

  // The number of Shuffler items to produce and store in the |input_file|.
  size_t number_of_items;
};

class Prochlo {
 public:
  Prochlo();

  // Move the configuration into the object and read the public keys.
  bool set_configuration(std::unique_ptr<Configuration> conf);

  // Creates the internal mapping for the output array to the output file,
  // stretches the file to the appropriate size, and sets the mapping as
  // sequentially scanned.
  bool setup_output();

  // Generates |number_of_items| random ShufflerItems.
  bool GenerateRandomShufflerItems();

  // Generate a fresh Prochlomation given the |metric| and |*data|, and package
  // it into a ShufflerItem including the |*crowd_id|. Neither |data| nor
  // |crowd_id| may be NULL, and they both must hold at least
  // |kProchlomationDataLength| and |kCrowdIdLength| allocated space,
  // respectively. The ShufflerItem is stored in |*shuffler_item|, which cannot
  // be NULL, and should have enough allocated space (i.e.,
  // |kShufflerItemLength|). Returns true on success, and fals otherwise.
  bool MakeProchlomation(uint64_t metric, const uint8_t* data,
                         const uint8_t* crowd_id, ShufflerItem* shuffler_item);

  ~Prochlo();

 private:
  std::unique_ptr<Configuration> conf_;

  Crypto crypto_;

  // The array of output ShufflerItems.
  ShufflerItem* shuffler_items_;

  // The (intended) size of the shuffler array, in bytes.
  size_t shuffler_array_size_;

  // The file descriptor of the output file.
  int file_descriptor_output_;
};

}  // namespace prochlo

#endif  // __LIB_PROCHLO_H__
