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
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fstream>
#include <streambuf>
#include <string>

#include "shuffle_data.h"

#include "sgx_eid.h"   /* sgx_enclave_id_t */
#include "sgx_error.h" /* sgx_status_t */

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define TOKEN_FILENAME "enclave.token"
#define ENCLAVE_FILENAME "enclave.signed.so"

#include <pwd.h>
#include <unistd.h>
#define MAX_PATH FILENAME_MAX

#include "Enclave_u.h"
#include "sgx_urts.h"

using prochlo::shuffler::AnalyzerItem;
using prochlo::shuffler::IntermediateShufflerItem;
using prochlo::shuffler::ShufflerItem;

sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
  sgx_status_t err;
  const char* msg;
  const char* sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL},
    {SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL},
    {SGX_ERROR_NO_DEVICE, "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX "
     "driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL},
    {SGX_ERROR_DEVICE_BUSY, "SGX device was busy.", NULL},
    {SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

  for (idx = 0; idx < ttl; idx++) {
    if (ret == sgx_errlist[idx].err) {
      if (NULL != sgx_errlist[idx].sug)
        printf("Info: %s\n", sgx_errlist[idx].sug);
      printf("Error: %s\n", sgx_errlist[idx].msg);
      break;
    }
  }

  if (idx == ttl) printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void) {
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;

  /* Step 1: try to retrieve the launch token saved by last transaction
   *         if there is no token, then create a new one.
   */
  /* try to get the token saved in $HOME */
  const char* home_dir = getpwuid(getuid())->pw_dir;

  if (home_dir != NULL && (strlen(home_dir) + strlen("/") +
                           sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
    /* compose the token path */
    strncpy(token_path, home_dir, strlen(home_dir));
    strncat(token_path, "/", strlen("/"));
    strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
  } else {
    /* if token path is too long or $HOME is NULL */
    strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
  }

  FILE* fp = fopen(token_path, "rb");
  if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
    printf("Warning: Failed to create/open the launch token file \"%s\".\n",
           token_path);
  }

  if (fp != NULL) {
    /* read the token from saved file */
    size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
    if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
      /* if token is invalid, clear the buffer */
      memset(&token, 0x0, sizeof(sgx_launch_token_t));
      printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
    }
  }
  /* Step 2: call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                           &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    printf("Ahhh!!! (%i)\n", ret);
    print_error_message(ret);
    if (fp != NULL) fclose(fp);
    return -1;
  }

  /* Step 3: save the launch token if it is updated */
  if (updated == FALSE || fp == NULL) {
    /* if the token is not updated, or file handler is invalid, do not perform
     * saving */
    if (fp != NULL) fclose(fp);
    return 0;
  }

  /* reopen the file with write capablity */
  fp = freopen(token_path, "wb", fp);
  if (fp == NULL) return 0;
  size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
  if (write_num != sizeof(sgx_launch_token_t))
    printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
  fclose(fp);
  return 0;
}

/* OCall functions */
void ocall_print_string(const char* str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("*%s", str);
  fflush(stdout);
}

static struct timeval tv_start, tv_end;

void ocall_do_gettimeofday_start() {
  if (gettimeofday(&tv_start, NULL)) {
    printf("gettimeofday start error\n");
  }
}

void ocall_do_gettimeofday_end(uint64_t n) {
  if (gettimeofday(&tv_end, NULL)) {
    printf("gettimeofday end error\n");
  }

  printf("Time difference for n=%lu is %lu s, %lu us\n", n,
         (tv_end.tv_usec > tv_start.tv_usec)
             ? (tv_end.tv_sec - tv_start.tv_sec)
             : (tv_end.tv_sec - tv_start.tv_sec - 1),
         (tv_end.tv_usec > tv_start.tv_usec)
             ? (tv_end.tv_usec - tv_start.tv_usec)
             : (1000000 + tv_end.tv_usec - tv_start.tv_usec));
  fflush(stdout);
}

/* Application entry */
int SGX_CDECL main(int argc, char* argv[]) {
  (void)(argc);
  (void)(argv);

  if (argc < 11) {
    perror(
        "Incorrect number of arguments.\n"
        "<number_of_items> <number_of_buckets> <chunk_size>\n"
        "<stash_size> <stash_chunks> <clean_up_window>\n"
        "<input_filename> <intermediate_filename> <output_filename>\n"
        "<private_key_filename>\n");
    return -1;
  }
  size_t number_of_items = atoi(argv[1]);
  size_t number_of_buckets = atoi(argv[2]);
  size_t chunk_size = atoi(argv[3]);
  size_t stash_size = atoi(argv[4]);
  size_t stash_chunks = atoi(argv[5]);
  // size_t clean_up_window = atoi(argv[6]);
  char* input_filename = argv[7];
  char* intermediate_filename = argv[8];
  //  char* output_filename = argv[9];
  char* private_key_filename = argv[10];

  size_t number_of_intermediate_items =
      chunk_size * (number_of_buckets + stash_chunks) * number_of_buckets;
  size_t intermediate_array_size =
      number_of_intermediate_items * sizeof(IntermediateShufflerItem);
  size_t input_array_size =
      number_of_items * sizeof(prochlo::shuffler::ShufflerItem);

  int seek_result;
  struct stat stat_buffer;
  int write_result;
  void* map;

  // ShufflerItems
  int file_descriptor_input = open(input_filename, O_RDONLY);
  if (file_descriptor_input == -1) {
    perror("Error opening input file for reading");
    exit(EXIT_FAILURE);
  }
  if (fstat(file_descriptor_input, &stat_buffer) ==
      -1) { /* To obtain file size */
    perror("Couldn't fstat input file.");
    exit(EXIT_FAILURE);
  }
  if ((size_t)stat_buffer.st_size < input_array_size) {
    fprintf(stderr,
            "Input file too small (%ld) for the number of items (%ld). Should "
            "be %ld.\n",
            stat_buffer.st_size, number_of_items, input_array_size);
    exit(EXIT_FAILURE);
  }
  map = mmap(0, input_array_size, PROT_READ, MAP_SHARED, file_descriptor_input,
             0);
  if (map == MAP_FAILED) {
    perror("Error mmapping the input array");
    exit(EXIT_FAILURE);
  }
  int madvise_result = madvise(map, input_array_size, MADV_SEQUENTIAL);
  if (madvise_result == -1) {
    perror("madvise MADV_SEQUENTIAL failed");
    exit(EXIT_FAILURE);
  }
  madvise_result = madvise(map, input_array_size, MADV_DONTDUMP);
  if (madvise_result == -1) {
    perror("madvise MADV_DONTDUMP failed");
    exit(EXIT_FAILURE);
  }
  ShufflerItem* encrypted_items = reinterpret_cast<ShufflerItem*>(map);

  // IntermediateShufflerItems
  int file_descriptor_intermediate =
      open(intermediate_filename, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600);
  if (file_descriptor_intermediate == -1) {
    perror("Error opening intermediate file for writing");
    exit(EXIT_FAILURE);
  }
  seek_result = lseek(file_descriptor_intermediate, intermediate_array_size - 1,
                      SEEK_SET);
  if (seek_result == -1) {
    close(file_descriptor_intermediate);
    perror("Error calling lseek() to 'stretch' the intermediate file");
    exit(EXIT_FAILURE);
  }
  write_result = write(file_descriptor_intermediate, "", 1);
  if (write_result != 1) {
    close(file_descriptor_intermediate);
    perror("Error writing last byte of the intermediate file");
    exit(EXIT_FAILURE);
  }
  map = mmap(0, intermediate_array_size, PROT_READ | PROT_WRITE, MAP_SHARED,
             file_descriptor_intermediate, 0);
  if (map == MAP_FAILED) {
    perror("Error mmapping the intermediate array");
    exit(EXIT_FAILURE);
  }
  IntermediateShufflerItem* encrypted_intermediate_items =
      reinterpret_cast<IntermediateShufflerItem*>(map);

  printf(
      "Distributing with data size=%lu, crowd ID size=%lu, ShufflerItem "
      "length=%lu, AnalyzerItem length=%lu, IntermediateShufflerItem "
      "length=%lu\n",
      prochlo::shuffler::kProchlomationDataLength,
      prochlo::shuffler::kCrowdIdLength, prochlo::shuffler::kShufflerItemLength,
      prochlo::shuffler::kAnalyzerItemLength,
      prochlo::shuffler::kIntermediateShufflerItemSize);

  /* Initialize the enclave */
  if (initialize_enclave() < 0) {
    printf("Enter a character before exit ...\n");
    getchar();
    return -1;
  }

  struct timeval tv_start, tv_end;

  if (gettimeofday(&tv_start, NULL)) printf("gettimeofday start error\n");

  std::ifstream key_stream(private_key_filename);
  std::string private_key_pem((std::istreambuf_iterator<char>(key_stream)),
                              std::istreambuf_iterator<char>());

  ecall_set_key(global_eid, private_key_pem.c_str());

  // Note that this uses an empty symmetric key
  uint8_t symmetric_key[prochlo::shuffler::kSymmetricKeyLength];
  memset(symmetric_key, 0, prochlo::shuffler::kSymmetricKeyLength);
  printf("XXXXXX\nXXXXX Running with a dummy symmetric key\nXXXXX\n");

  sgx_status_t result =
      ecall_distribute(global_eid, (void*)encrypted_items, number_of_items,
                       number_of_buckets, chunk_size, stash_size, stash_chunks,
                       (void*)encrypted_intermediate_items, symmetric_key);
  if (result != SGX_SUCCESS) {
    printf("ecall_distribute failed with error code (%i)\n", result);
    print_error_message(result);
  } else {
    printf("ecall_distribute succeeded.\n");
  }

  if (gettimeofday(&tv_end, NULL)) printf("gettimeofday end error\n");

  printf("Time difference is %lu s, %lu us\n",
         (tv_end.tv_usec > tv_start.tv_usec)
             ? (tv_end.tv_sec - tv_start.tv_sec)
             : (tv_end.tv_sec - tv_start.tv_sec - 1),
         (tv_end.tv_usec > tv_start.tv_usec)
             ? (tv_end.tv_usec - tv_start.tv_usec)
             : (1000000 + tv_end.tv_usec - tv_start.tv_usec));

  /* Don't forget to free the mmapped memory
   */
  if (munmap(encrypted_intermediate_items, intermediate_array_size) == -1) {
    perror("Error un-mmapping the intermediate array");
  }
  if (munmap(encrypted_items, input_array_size) == -1) {
    perror("Error un-mmapping the input file");
  }

  // Un-mmap-ing doesn't close the file, so we still need to do that.
  close(file_descriptor_intermediate);
  close(file_descriptor_input);

  /* Destroy the enclave */
  sgx_destroy_enclave(global_eid);

  printf("Stash Shuffler completed successfully.\n");

  return 0;
}
