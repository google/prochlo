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

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cstring>
#include <iostream>
#include <string>

#include <lib/prochlo.h>

namespace prochlo {

const char* const Configuration::USAGE =
    "-h    help\n"
    "-o    <output file>\n"
    "-S    <shuffler key file>\n"
    "-A    <analyzer key file>\n"
    "-n    <number of items>\n";

int Configuration::parse_args(int argc, char* argv[]) {
  int ch;

  while ((ch = getopt(argc, argv, "ho:S:A:n:")) != -1) {
    switch (ch) {
      case 'o':
        output_file = optarg;
        break;

      case 'S':
        shuffler_key_file = optarg;
        break;

      case 'A':
        analyzer_key_file = optarg;
        break;

      case 'n':
        number_of_items = strtoul(optarg, NULL, 10);
        break;

      case 'h':
      default:
        return -1;
    }
  }

  return optind;
}

Prochlo::Prochlo()
    : shuffler_items_(nullptr),
      shuffler_array_size_(0),
      file_descriptor_output_(0) {}

bool Prochlo::set_configuration(std::unique_ptr<Configuration> conf) {
  conf_ = std::move(conf);

  // Load Analyzer and Shuffler Keys
  if (!crypto_.load_shuffler_key(conf_->shuffler_key_file)) {
    fprintf(stderr, "load_shuffler_key()\n");
    return false;
  }

  if (!crypto_.load_analyzer_key(conf_->analyzer_key_file)) {
    fprintf(stderr, "load_analyzer_key()\n");
    return false;
  }

  return true;
}

// Set up the output file, size it appropriately, and mmap it.
bool Prochlo::setup_output() {
  file_descriptor_output_ = open(conf_->output_file.c_str(),
                                 O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600);
  if (file_descriptor_output_ == -1) {
    warn("Error opening output file '%s' for writing.",
         conf_->output_file.c_str());
    return false;
  }

  // If the number of items is 0, just exit successfully.
  if (conf_->number_of_items == 0) {
    close(file_descriptor_output_);
    return true;
  }

  shuffler_array_size_ = conf_->number_of_items * kShufflerItemLength;
  int seek_result =
      lseek(file_descriptor_output_, shuffler_array_size_ - 1, SEEK_SET);
  if (seek_result == -1) {
    close(file_descriptor_output_);
    warn(
        "Error calling lseek() to 'stretch' the output file %s up to "
        "%lu bytes down.",
        conf_->output_file.c_str(), shuffler_array_size_);
    return false;
  }

  /* Something needs to be written at the end of the file to have the file
   * actually have the new size.
   */
  int write_result = write(file_descriptor_output_, "", 1);
  if (write_result != 1) {
    close(file_descriptor_output_);
    warn("Error writing last byte of the output file.");
    return false;
  }

  /* Now the file is ready to be mmapped. */
  void* map = mmap(0, shuffler_array_size_, PROT_READ | PROT_WRITE, MAP_SHARED,
                   file_descriptor_output_, 0);
  if (map == MAP_FAILED) {
    close(file_descriptor_output_);
    warn("Error mmapping the output array.");
    return false;
  }
  int madvise_result = madvise(map, shuffler_array_size_, MADV_SEQUENTIAL);
  if (madvise_result == -1) {
    close(file_descriptor_output_);
    warn("madvise MADV_SEQUENTIAL failed");
    return false;
  }
  madvise_result = madvise(map, shuffler_array_size_, MADV_DONTDUMP);
  if (madvise_result == -1) {
    close(file_descriptor_output_);
    warn("madvise MADV_DONTDUMP failed");
    return false;
  }
  shuffler_items_ = reinterpret_cast<ShufflerItem*>(map);
  return true;
}

// Generate |number_of_items| ShufflerItems. Generate two ephemeral key pairs
// for each (one for the encryption to the Analyzer, and one for the encryption
// to the Shuffler). Make the data random. Since this demo doesn't show
// thresholding, make crowd IDs random as well. Use the same (dummy) metric for
// all data.
bool Prochlo::GenerateRandomShufflerItems() {
  for (size_t index = 0; index < conf_->number_of_items; index++) {
    ShufflerItem& item = shuffler_items_[index];

    uint8_t data[kProchlomationDataLength];
    uint8_t crowd_id[kCrowdIdLength];
    uint64_t metric = METRIC_STRING_TEST;

    // For the purposes of this demo, drawing data with a more interesting
    // probability distribution makes little difference. For |crowd_id| it's
    // nice to have a predictable value, to check that cryptography didn't go
    // awry.
    memset(data, 0, kProchlomationDataLength);
    memset(crowd_id, static_cast<uint8_t>(index * 3), kCrowdIdLength);

    if (index % kGenerationReportingInterval == 0) {
      printf("At index %lu.\n", index);
    }

    if (!MakeProchlomation(metric, data, crowd_id, &item)) {
      warn("Failed to construct a ShufflerItem from a Prochlomation.");
      return false;
    }
  }

  return true;
}

Prochlo::~Prochlo() {
  // Fee the mmapped memory.
  if (munmap(shuffler_items_, shuffler_array_size_) == -1) {
    warn("Error un-mmapping the output array");
  }
  shuffler_items_ = nullptr;

  // Un-mmap-ing doesn't close the file, so we still need to do that.
  close(file_descriptor_output_);
  file_descriptor_output_ = 0;
}

bool Prochlo::MakeProchlomation(uint64_t metric, const uint8_t* data,
                                const uint8_t* crowd_id,
                                ShufflerItem* shuffler_item) {
  assert(data != nullptr);
  assert(crowd_id != nullptr);
  assert(shuffler_item != nullptr);

  // We have to create a Prochlomation and a PlainShufflerItem to encrypt them
  // both into an AnalyzerItem and a ShufflerItem, respectively. We'll stage
  // those here. We can probably do this more efficiently to avoid copies.
  Prochlomation prochlomation;
  PlainShufflerItem plain_shuffler_item;

  // First the prochlomation
  prochlomation.metric = metric;
  memcpy(prochlomation.data, data, kProchlomationDataLength);

  // Then the AnalyzerItem of the PlainShufflerItem
  if (!crypto_.EncryptForAnalyzer(prochlomation,
                                  &plain_shuffler_item.analyzer_item)) {
    warn("Failed to encrypt_for_analyzer.\n");
    return false;
  }

  // Now prepare the PlainShufflerItem
  memcpy(plain_shuffler_item.crowd_id, crowd_id, kCrowdIdLength);

  // And create the ShufflerItem
  if (!crypto_.EncryptForShuffler(plain_shuffler_item, shuffler_item)) {
    warn("Failed to encrypt_for_shuffler.\n");
    return false;
  }

  return true;
}

}  // namespace prochlo
