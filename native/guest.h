#ifndef RUBY_GUEST_H
#define RUBY_GUEST_H
#include <stdint.h>
#include <stddef.h>

/* Flat, immutable value tree. Rust owns all input/reply storage. C creates Ruby
 * values only after returning from Rust, inside a C-only protected boundary. */
typedef struct {
  int kind; /* nil, false, true, integer, float, string, array, map */
  int64_t integer;
  double number;
  const unsigned char *text;
  size_t length;
} ruby_node;

typedef struct {
  const char *source;
  size_t source_length;
  const char *filename;
  const ruby_node *globals;
  const ruby_node *catalog;
  size_t memory_limit;
  uint64_t instruction_limit;
  size_t result_limit;
  int validate_only;
  int capabilities;
  void *host;
} ruby_request;

typedef struct {
  char *json;
  size_t json_length;
  char error[2048];
  char error_type[64];
  int line;
  int column;
  int status;
  size_t peak_memory;
  uint64_t instructions;
} ruby_result;

/* Callback never calls mruby. Returned nodes remain owned by Rust until the
 * next callback. Nonzero status is converted to a Ruby exception in C. */
extern int ruby_host_call(void *host, const char *kind, const char *path,
  const char *json, size_t length, const ruby_node **reply);
void ruby_execute(const ruby_request *request, ruby_result *result);
void ruby_result_free(ruby_result *result);
#endif
