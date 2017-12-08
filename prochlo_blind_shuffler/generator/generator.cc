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

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <memory>

#include <lib/prochlo.h>

using prochlo::Configuration;
using prochlo::Prochlo;

int main(int argc, char* argv[]) {
  auto configuration = std::unique_ptr<Configuration>(new Configuration());

  if (configuration->parse_args(argc, argv) < 0) {
    printf("Usage: %s <opts> \n%s", argv[0], Configuration::USAGE);
    return -1;
  }

  Prochlo prochlo;

  if (!prochlo.set_configuration(std::move(configuration))) {
    warn("set_configuration()");
    return -1;
  }

  // mmap the input file.
  // Make the file sequential.
  if (!prochlo.setup_output()) {
    warn("setup_output()");
    return -1;
  }

  printf(
      "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
      "Starting file generation. Don't forget to save the private\n"
      "keys along with the generated file, if you hope to shuffle the file\n"
      "later!!!.\n"
      "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");

  // For count of prochlomations, generate blinder item and write it to the
  // file.
  if (!prochlo.GenerateRandomBlinderItems()) {
    warn("generate_random_blinder_items failed.");
    return -1;
  }

  printf("Input-file generation complete.\n");
  return 0;
}
