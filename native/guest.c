/* The complete mruby ownership boundary lives in C. No Ruby allocation or
 * exception propagation occurs in a Rust frame, including host callbacks. */
#include "guest.h"
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/internal.h>
#include <mruby/irep.h>
#include <mruby/opcode.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

typedef union { size_t size; max_align_t alignment; } allocation;
typedef struct {
  const ruby_request *request;
  ruby_result *result;
  size_t allocated;
  mrb_value catalog;
  mrb_value globals;
  struct RClass *record_class;
  struct RClass *path_class;
  struct RClass *error_class;
  mrb_value exception;
} guest_state;

/* mruby 4 uses a link-time allocator override. This process owns exactly one
 * VM on one thread; the supervisor never constructs a VM. */
static guest_state *active_state;

/* Budget exhaustion terminates the disposable process: Ruby rescue/ensure
 * cannot reset a budget or run indefinitely while handling a limit error. */
void *mrb_basic_alloc_func(void *pointer, size_t size) {
  guest_state *state = active_state;
  if (!state) _exit(125);
  allocation *old = pointer ? (allocation*)pointer - 1 : NULL;
  size_t previous = old ? old->size : 0;
  if (size == 0) { free(old); state->allocated -= previous; return NULL; }
  if (size > state->request->memory_limit ||
      state->allocated - previous > state->request->memory_limit - size ||
      size > SIZE_MAX - sizeof(allocation)) _exit(125);
  allocation *next = realloc(old, sizeof(allocation) + size);
  if (!next) _exit(125);
  next->size = size;
  state->allocated = state->allocated - previous + size;
  if (state->allocated > state->result->peak_memory)
    state->result->peak_memory = state->allocated;
  return next + 1;
}

static void instruction_hook(mrb_state *mrb, const mrb_irep *irep,
                             const mrb_code *pc, mrb_value *registers) {
  (void)irep; (void)pc; (void)registers;
  guest_state *state = mrb->ud;
  if (++state->result->instructions > state->request->instruction_limit) _exit(124);
}

static mrb_value text_key(mrb_state *mrb, mrb_value key) {
  if (mrb_symbol_p(key)) return mrb_sym_str(mrb, mrb_symbol(key));
  if (!mrb_string_p(key)) mrb_raise(mrb, E_TYPE_ERROR, "Object keys must be strings or symbols");
  return key;
}

static mrb_value record_data(mrb_state *mrb, mrb_value self) {
  mrb_value data = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@data"));
  if (!mrb_hash_p(data)) mrb_raise(mrb, E_TYPE_ERROR, "Invalid Record");
  return data;
}

static mrb_value record_get(mrb_state *mrb, mrb_value self) {
  mrb_value key;
  mrb_get_args(mrb, "o", &key);
  return mrb_hash_get(mrb, record_data(mrb, self), text_key(mrb, key));
}

static mrb_value record_fetch(mrb_state *mrb, mrb_value self) {
  mrb_value key, fallback = mrb_nil_value();
  mrb_int count = mrb_get_args(mrb, "o|o", &key, &fallback);
  key = text_key(mrb, key);
  mrb_value data = record_data(mrb, self);
  if (mrb_hash_key_p(mrb, data, key)) return mrb_hash_get(mrb, data, key);
  if (count > 1) return fallback;
  mrb_raise(mrb, E_KEY_ERROR, "Record key is missing; use [] for an optional field");
  return mrb_nil_value();
}

static mrb_value record_field(mrb_state *mrb, mrb_value self) {
  mrb_sym name;
  mrb_get_args(mrb, "n", &name);
  mrb_value key = mrb_sym_str(mrb, name), data = record_data(mrb, self);
  if (!mrb_hash_key_p(mrb, data, key)) mrb_raise(mrb, E_NOMETHOD_ERROR, "Unknown Record field; inspect keys");
  return mrb_hash_get(mrb, data, key);
}

static mrb_value record_keys(mrb_state *mrb, mrb_value self) {
  return mrb_hash_keys(mrb, record_data(mrb, self));
}

static mrb_value record_length(mrb_state *mrb, mrb_value self) {
  return mrb_int_value(mrb, mrb_hash_size(mrb, record_data(mrb, self)));
}

static mrb_value record_values(mrb_state *mrb, mrb_value self) {
  return mrb_hash_values(mrb, record_data(mrb, self));
}

static mrb_value record_pairs(mrb_state *mrb, mrb_value self) {
  mrb_value data = record_data(mrb, self), keys = mrb_hash_keys(mrb, data);
  mrb_value pairs = mrb_ary_new_capa(mrb, RARRAY_LEN(keys));
  for (mrb_int i = 0; i < RARRAY_LEN(keys); i++) {
    mrb_value key = mrb_ary_ref(mrb, keys, i);
    mrb_value pair[2] = {key, mrb_hash_get(mrb, data, key)};
    mrb_ary_push(mrb, pairs, mrb_ary_new_from_values(mrb, 2, pair));
  }
  return pairs;
}

static mrb_value decode(mrb_state *mrb, const ruby_node **cursor, int depth, int records) {
  if (depth > 64) mrb_raise(mrb, E_RANGE_ERROR, "Value exceeds nesting limit");
  const ruby_node *node = (*cursor)++;
  mrb_value value = mrb_nil_value();
  switch (node->kind) {
    case 0: return value;
    case 1: return mrb_false_value();
    case 2: return mrb_true_value();
    case 3: return mrb_int_value(mrb, node->integer);
    case 4: return mrb_float_value(mrb, node->number);
    case 5: value = mrb_str_new(mrb, (const char*)node->text, node->length); break;
    case 6:
      value = mrb_ary_new_capa(mrb, node->length);
      for (size_t i = 0; i < node->length; i++) mrb_ary_push(mrb, value, decode(mrb, cursor, depth+1, records));
      break;
    case 7:
      value = mrb_hash_new_capa(mrb, node->length);
      for (size_t i = 0; i < node->length; i++) {
        mrb_value key = decode(mrb, cursor, depth+1, 0);
        mrb_value item = decode(mrb, cursor, depth+1, records);
        mrb_hash_set(mrb, value, key, item);
      }
      mrb_obj_freeze(mrb, value);
      if (records) {
        guest_state *state = mrb->ud;
        mrb_value record = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_OBJECT, state->record_class));
        mrb_iv_set(mrb, record, mrb_intern_lit(mrb, "@data"), value);
        value = record;
      }
      break;
    default: mrb_raise(mrb, E_TYPE_ERROR, "Invalid host value");
  }
  return mrb_obj_freeze(mrb, value);
}

static void append(mrb_state *mrb, mrb_value output, const char *bytes, size_t length) {
  guest_state *state = mrb->ud;
  if (length > state->request->result_limit ||
      (size_t)RSTRING_LEN(output) > state->request->result_limit - length)
    mrb_raise(mrb, E_RANGE_ERROR, "Encoded value exceeds byte limit; return a smaller summary");
  mrb_str_cat(mrb, output, bytes, length);
}

static void quote(mrb_state *mrb, mrb_value output, mrb_value text) {
  append(mrb, output, "\"", 1);
  for (mrb_int i = 0; i < RSTRING_LEN(text); i++) {
    unsigned char c = (unsigned char)RSTRING_PTR(text)[i];
    if (c == '"' || c == '\\') {
      char escaped[2] = {'\\', (char)c}; append(mrb, output, escaped, 2);
    } else if (c < 32) {
      char escaped[7]; snprintf(escaped, sizeof(escaped), "\\u%04x", c);
      append(mrb, output, escaped, 6);
    } else append(mrb, output, (const char*)&c, 1);
  }
  append(mrb, output, "\"", 1);
}

/* Conversion never calls user-defined to_json/to_s/inspect. The depth limit
 * rejects cycles as well as deeply nested acyclic data. */
static void encode(mrb_state *mrb, mrb_value output, mrb_value value, int depth) {
  if (depth > 64) mrb_raise(mrb, E_RANGE_ERROR, "Cyclic or excessively nested result");
  guest_state *state = mrb->ud;
  if (mrb_obj_is_kind_of(mrb, value, state->record_class)) value = record_data(mrb, value);
  char number[64];
  if (mrb_nil_p(value)) append(mrb, output, "null", 4);
  else if (mrb_false_p(value)) append(mrb, output, "false", 5);
  else if (mrb_true_p(value)) append(mrb, output, "true", 4);
  else if (mrb_integer_p(value)) {
    int n = snprintf(number, sizeof(number), "%lld", (long long)mrb_integer(value));
    append(mrb, output, number, n);
  } else if (mrb_float_p(value)) {
    double f = mrb_float(value);
    if (!isfinite(f)) mrb_raise(mrb, E_TYPE_ERROR, "Non-finite numbers cannot cross the host boundary");
    int n = snprintf(number, sizeof(number), "%.17g", f);
    append(mrb, output, number, n);
    if (!strchr(number, '.') && !strchr(number, 'e') && !strchr(number, 'E')) append(mrb, output, ".0", 2);
  } else if (mrb_string_p(value) || mrb_symbol_p(value)) quote(mrb, output, text_key(mrb, value));
  else if (mrb_array_p(value)) {
    append(mrb, output, "[", 1);
    for (mrb_int i = 0; i < RARRAY_LEN(value); i++) {
      if (i) append(mrb, output, ",", 1);
      encode(mrb, output, mrb_ary_ref(mrb, value, i), depth+1);
    }
    append(mrb, output, "]", 1);
  } else if (mrb_hash_p(value)) {
    mrb_value keys = mrb_hash_keys(mrb, value), seen = mrb_hash_new(mrb);
    append(mrb, output, "{", 1);
    for (mrb_int i = 0; i < RARRAY_LEN(keys); i++) {
      mrb_value raw = mrb_ary_ref(mrb, keys, i), key = text_key(mrb, raw);
      if (mrb_hash_key_p(mrb, seen, key)) mrb_raise(mrb, E_TYPE_ERROR, "Duplicate normalized string/symbol key");
      mrb_hash_set(mrb, seen, key, mrb_true_value());
      if (i) append(mrb, output, ",", 1);
      quote(mrb, output, key); append(mrb, output, ":", 1);
      encode(mrb, output, mrb_hash_get(mrb, value, raw), depth+1);
    }
    append(mrb, output, "}", 1);
  } else mrb_raise(mrb, E_TYPE_ERROR, "Unsupported result type; return structured data");
}

static mrb_value exchange(mrb_state *mrb, const char *kind, mrb_value path, mrb_value args) {
  guest_state *state = mrb->ud;
  mrb_value json = mrb_str_new_lit(mrb, "");
  encode(mrb, json, args, 0);
  const ruby_node *reply = NULL;
  int status = ruby_host_call(state->request->host, kind, mrb_str_to_cstr(mrb, path),
      RSTRING_PTR(json), RSTRING_LEN(json), &reply);
  if (status || !reply) mrb_raise(mrb, E_RUNTIME_ERROR, "Host protocol failed");
  mrb_value envelope = record_data(mrb, decode(mrb, &reply, 0, 1));
  mrb_value ok = mrb_hash_get(mrb, envelope, mrb_str_new_lit(mrb, "ok"));
  if (!mrb_true_p(ok)) {
    mrb_value error = mrb_hash_get(mrb, envelope, mrb_str_new_lit(mrb, "message"));
    if (!mrb_string_p(error)) error = mrb_str_new_lit(mrb, "Capability call failed");
    mrb_value exception = mrb_exc_new_str(mrb, state->error_class, error);
    mrb_value code = mrb_hash_get(mrb, envelope, mrb_str_new_lit(mrb, "code"));
    if (mrb_string_p(code)) mrb_iv_set(mrb, exception, mrb_intern_lit(mrb, "@code"), code);
    mrb_exc_raise(mrb, exception);
  }
  return mrb_hash_get(mrb, envelope, mrb_str_new_lit(mrb, "value"));
}

static mrb_value path_new(mrb_state *mrb, mrb_value path) {
  guest_state *state = mrb->ud;
  mrb_value object = mrb_obj_value(mrb_obj_alloc(mrb, MRB_TT_OBJECT, state->path_class));
  mrb_iv_set(mrb, object, mrb_intern_lit(mrb, "@path"), mrb_obj_freeze(mrb, path));
  return mrb_obj_freeze(mrb, object);
}

/* Pure data helpers reuse the same bounded conversion as the host protocol.
 * Parsing runs in Rust without calling the host or granting any capability. */
static mrb_value json_generate(mrb_state *mrb, mrb_value self) {
  (void)self;
  mrb_value value;
  mrb_get_args(mrb, "o", &value);
  mrb_value output = mrb_str_new_lit(mrb, "");
  encode(mrb, output, value, 0);
  return output;
}

static mrb_value json_parse(mrb_state *mrb, mrb_value self) {
  (void)self;
  mrb_value value;
  mrb_get_args(mrb, "S", &value);
  return exchange(mrb, "json", mrb_str_new_lit(mrb, ""), value);
}

static mrb_value app_root(mrb_state *mrb, mrb_value self) {
  (void)self;
  guest_state *state = mrb->ud;
  if (!state->request->capabilities) mrb_raise(mrb, E_RUNTIME_ERROR, "app capabilities are unavailable in this profile");
  return path_new(mrb, mrb_str_new_lit(mrb, ""));
}

static mrb_value app_dispatch(mrb_state *mrb, mrb_value self) {
  mrb_sym name; mrb_value *args; mrb_int count;
  mrb_get_args(mrb, "n*", &name, &args, &count);
  mrb_value prefix = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@path"));
  if (!mrb_string_p(prefix)) mrb_raise(mrb, E_TYPE_ERROR, "Invalid capability path");
  mrb_value path = mrb_str_dup(mrb, prefix);
  if (RSTRING_LEN(path)) mrb_str_cat_lit(mrb, path, ".");
  mrb_str_concat(mrb, path, mrb_sym_str(mrb, name));
  guest_state *state = mrb->ud;
  for (mrb_int i = 0; i < RARRAY_LEN(state->catalog); i++) {
    mrb_value candidate = mrb_ary_ref(mrb, state->catalog, i);
    if (mrb_str_equal(mrb, path, candidate))
      return exchange(mrb, "call", path, mrb_ary_new_from_values(mrb, count, args));
  }
  /* Navigation is valid only when a catalog terminal exists below the prefix.
   * Unknown zero-argument methods must not silently return a namespace object. */
  int namespace = 0;
  for (mrb_int i = 0; !count && i < RARRAY_LEN(state->catalog); i++) {
    mrb_value candidate = mrb_ary_ref(mrb, state->catalog, i);
    if (RSTRING_LEN(candidate) > RSTRING_LEN(path)
        && !memcmp(RSTRING_PTR(candidate), RSTRING_PTR(path), RSTRING_LEN(path))
        && RSTRING_PTR(candidate)[RSTRING_LEN(path)] == '.') { namespace = 1; break; }
  }
  if (!namespace) return exchange(mrb, "unknown", path, mrb_nil_value());
  return path_new(mrb, path);
}

/* Exact string-addressed calls handle Ruby-reserved provider identifiers. The
 * catalog restriction and application callback remain identical to dotted calls. */
static mrb_value app_call(mrb_state *mrb, mrb_value self) {
  (void)self;
  mrb_value path, *args; mrb_int count;
  mrb_get_args(mrb, "S*", &path, &args, &count);
  guest_state *state = mrb->ud;
  for (mrb_int i = 0; i < RARRAY_LEN(state->catalog); i++) {
    if (mrb_str_equal(mrb, path, mrb_ary_ref(mrb, state->catalog, i)))
      return exchange(mrb, "call", path, mrb_ary_new_from_values(mrb, count, args));
  }
  return exchange(mrb, "unknown", path, mrb_nil_value());
}

static mrb_value capture(mrb_state *mrb, mrb_value self) {
  (void)self;
  mrb_value *args; mrb_int count;
  mrb_get_args(mrb, "*", &args, &count);
  return exchange(mrb, "log", mrb_str_new_lit(mrb, ""), mrb_ary_new_from_values(mrb, count, args));
}

static mrb_value context_get(mrb_state *mrb, mrb_value self) {
  (void)self;
  guest_state *state = mrb->ud;
  return mrb_hash_get(mrb, state->globals, mrb_str_new_lit(mrb, "ctx"));
}

/* Admission examines compiler-produced instructions/symbols, never raw source
 * text. This is a restricted profile check, not the OS containment boundary. */
static const mrb_code *next_instruction(const mrb_code *pc) {
  unsigned int a = 0, b = 0, c = 0;
  mrb_code instruction = READ_B();
  switch (instruction) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x (); break;
#include <mruby/ops.h>
#undef OPCODE
  }
  switch (instruction) {
    case OP_EXT1:
      instruction = READ_B();
      switch (instruction) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _1 (); break;
#include <mruby/ops.h>
#undef OPCODE
      } break;
    case OP_EXT2:
      instruction = READ_B();
      switch (instruction) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _2 (); break;
#include <mruby/ops.h>
#undef OPCODE
      } break;
    case OP_EXT3:
      instruction = READ_B();
      switch (instruction) {
#define OPCODE(i,x) case OP_ ## i: FETCH_ ## x ## _3 (); break;
#include <mruby/ops.h>
#undef OPCODE
      } break;
  }
  (void)a; (void)b; (void)c;
  return pc;
}

static void admit(mrb_state *mrb, const mrb_irep *irep, int depth) {
  if (depth > 128) mrb_raise(mrb, E_RANGE_ERROR, "Compiler nesting limit exceeded");
  const char *forbidden[] = {"eval", "instance_eval", "class_eval", "module_eval", "require",
    "load", "autoload", "send", "__send__", "public_send", "define_method", "define_singleton_method",
    "const_get", "const_set", "remove_const", "instance_variable_set", "instance_variable_get",
    "class_variable_set", "class_variable_get", "singleton_class", "extend", "include", "prepend",
    "method_missing", "remove_method", "alias_method", "undef_method", "system", "exec", "spawn",
    "fork", "sleep", "rand", "srand", "binding", "ENV", "IO", "File", "Dir", "Process", "Thread",
    "Fiber", "Socket", "ObjectSpace", "Marshal", "Time", "Random", NULL};
  const mrb_code *pc = irep->iseq, *end = pc + irep->ilen;
  while (pc < end) {
    struct mrb_insn_data instruction = mrb_decode_insn(pc);
    switch (instruction.insn) {
      case OP_CLASS: case OP_MODULE: case OP_SCLASS: case OP_SDEF:
      case OP_ALIAS: case OP_UNDEF: case OP_SETCONST: case OP_SETMCNST: case OP_SETGV:
        mrb_raise(mrb, E_SYNTAX_ERROR, "Classes, monkey-patching and global mutation are outside opencompany-code-v1");
      /* Symbols used as data are not authority. In particular, include: and
       * :send are valid payloads even though invoking those methods is denied. */
      case OP_GETGV: case OP_GETCONST: case OP_GETMCNST: case OP_TDEF:
      case OP_SSEND: case OP_SSEND0: case OP_SSENDB:
      case OP_SEND: case OP_SEND0: case OP_SENDB: {
        if (instruction.b >= irep->slen) mrb_raise(mrb, E_SYNTAX_ERROR, "Invalid symbol reference");
        const char *name = mrb_sym_name(mrb, irep->syms[instruction.b]);
        for (const char **deny = forbidden; name && *deny; deny++)
          if (!strcmp(name, *deny)) mrb_raisef(mrb, E_SYNTAX_ERROR, "Unsupported Ruby profile capability: %s", *deny);
        break;
      }
    }
    const mrb_code *next = next_instruction(pc);
    if (next <= pc || next > end)
      mrb_raise(mrb, E_SYNTAX_ERROR, "Invalid compiler instruction boundary");
    pc = next;
  }
  for (uint16_t i = 0; i < irep->rlen; i++) admit(mrb, irep->reps[i], depth+1);
}

static mrb_value run(mrb_state *mrb, void *ud) {
  guest_state *state = ud;
  // Anonymous class: guest source cannot construct a trusted diagnostic tag.
  state->error_class = mrb_class_new(mrb, E_RUNTIME_ERROR);
  mrb_gc_register(mrb, mrb_obj_value(state->error_class));
  state->record_class = mrb_define_class(mrb, "Record", mrb->object_class);
  mrb_define_method(mrb, state->record_class, "[]", record_get, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, state->record_class, "fetch", record_fetch, MRB_ARGS_ARG(1,1));
  mrb_define_method(mrb, state->record_class, "keys", record_keys, MRB_ARGS_NONE());
  mrb_define_method(mrb, state->record_class, "values", record_values, MRB_ARGS_NONE());
  mrb_define_method(mrb, state->record_class, "to_a", record_pairs, MRB_ARGS_NONE());
  mrb_define_method(mrb, state->record_class, "length", record_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, state->record_class, "method_missing", record_field, MRB_ARGS_REQ(1));
  state->path_class = mrb_define_class(mrb, "CapabilityPath", mrb->object_class);
  mrb_define_method(mrb, state->path_class, "method_missing", app_dispatch, MRB_ARGS_ANY());
  mrb_define_method(mrb, state->path_class, "call", app_call, MRB_ARGS_ANY());
  mrb_define_method(mrb, mrb->kernel_module, "app", app_root, MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb->kernel_module, "ctx", context_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb->kernel_module, "puts", capture, MRB_ARGS_ANY());
  mrb_define_method(mrb, mrb->kernel_module, "p", capture, MRB_ARGS_ANY());
  struct RClass *json = mrb_define_module(mrb, "JSON");
  mrb_define_class_method(mrb, json, "generate", json_generate, MRB_ARGS_REQ(1));
  mrb_define_class_method(mrb, json, "parse", json_parse, MRB_ARGS_REQ(1));
  mrb_obj_freeze(mrb, mrb_obj_value(json));
  const ruby_node *cursor = state->request->globals;
  state->globals = record_data(mrb, decode(mrb, &cursor, 0, 1));
  mrb_gc_register(mrb, state->globals);
  cursor = state->request->catalog;
  state->catalog = decode(mrb, &cursor, 0, 0);
  mrb_gc_register(mrb, state->catalog);
  mrb_obj_freeze(mrb, mrb_obj_value(state->path_class));
  mrb_obj_freeze(mrb, mrb_obj_value(state->record_class));

  // Admission supplies helpful early diagnostics; removing these native entry
  // points is a separate runtime defense against reflective/dynamic invocation.
  const char *removed[] = {"send", "__send__", "public_send", "instance_eval", "class_eval", "module_eval",
    "define_method", "define_singleton_method", "const_get", "const_set", "remove_const",
    "instance_variable_get", "instance_variable_set", "class_variable_get", "class_variable_set",
    "singleton_class", "extend", "include", "prepend", "alias_method", "remove_method", "undef_method", NULL};
  struct RClass *owners[] = {mrb->object_class, mrb->kernel_module, mrb->module_class, mrb->class_class};
  for (size_t owner = 0; owner < sizeof(owners)/sizeof(owners[0]); owner++)
    for (const char **name = removed; *name; name++) mrb_undef_method(mrb, owners[owner], *name);

  mrb_ccontext *context = mrb_ccontext_new(mrb);
  context->capture_errors = TRUE;
  context->no_exec = TRUE;
  mrb_ccontext_filename(mrb, context, state->request->filename);
  struct mrb_parser_state *parser = mrb_parse_nstring(mrb, state->request->source,
      state->request->source_length, context);
  if (!parser) mrb_raise(mrb, E_SYNTAX_ERROR, "Unable to parse Ruby source");
  if (parser->nerr) {
    state->result->line = parser->error_buffer[0].lineno;
    state->result->column = parser->error_buffer[0].column;
    snprintf(state->result->error, sizeof(state->result->error), "%s", parser->error_buffer[0].message);
    state->result->status = 1;
    mrb_parser_free(parser); mrb_ccontext_free(mrb, context);
    return mrb_nil_value();
  }
  struct RProc *proc = mrb_generate_code(mrb, parser);
  mrb_parser_free(parser); mrb_ccontext_free(mrb, context);
  if (!proc) mrb_raise(mrb, E_SYNTAX_ERROR, "Ruby compilation failed");
  state->result->status = 3;
  admit(mrb, proc->body.irep, 0);
  state->result->status = 0;
  if (state->request->validate_only) return mrb_nil_value();
  mrb->code_fetch_hook = instruction_hook;
  mrb_value value = mrb_top_run(mrb, proc, mrb_top_self(mrb), 0);
  if (mrb->exc) mrb_exc_raise(mrb, mrb_obj_value(mrb->exc));
  mrb_value output = mrb_str_new_lit(mrb, "");
  encode(mrb, output, value, 0);
  state->result->json_length = RSTRING_LEN(output);
  state->result->json = malloc(state->result->json_length + 1);
  if (!state->result->json) _exit(125);
  memcpy(state->result->json, RSTRING_PTR(output), state->result->json_length);
  state->result->json[state->result->json_length] = 0;
  return mrb_nil_value();
}

/* Exception presentation stays protected too: native backtrace formatting can
 * allocate. Never dispatch a guest override of message/backtrace/inspect. */
static mrb_value error_details(mrb_state *mrb, void *ud) {
  guest_state *state = ud;
  if (state->error_class && mrb_obj_is_kind_of(mrb, state->exception, state->error_class)) {
    mrb_value code = mrb_iv_get(mrb, state->exception, mrb_intern_lit(mrb, "@code"));
    if (mrb_string_p(code)) snprintf(state->result->error_type, sizeof(state->result->error_type), "%.*s",
        (int)RSTRING_LEN(code), RSTRING_PTR(code));
  }
  mrb_value message = mrb_exc_mesg_get(mrb, (struct RException*)mrb_obj_ptr(state->exception));
  if (mrb_string_p(message)) snprintf(state->result->error, sizeof(state->result->error), "%.*s",
      (int)RSTRING_LEN(message), RSTRING_PTR(message));
  mrb_value trace = mrb_exc_backtrace(mrb, state->exception);
  if (mrb_array_p(trace)) {
    size_t prefix = strlen(state->request->filename);
    for (mrb_int i = 0; i < RARRAY_LEN(trace); i++) {
      mrb_value entry = mrb_ary_ref(mrb, trace, i);
      if (!mrb_string_p(entry) || (size_t)RSTRING_LEN(entry) <= prefix + 1) continue;
      if (memcmp(RSTRING_PTR(entry), state->request->filename, prefix) || RSTRING_PTR(entry)[prefix] != ':') continue;
      state->result->line = atoi(RSTRING_PTR(entry) + prefix + 1);
      state->result->column = -1;
      break;
    }
  }
  return mrb_nil_value();
}

void ruby_execute(const ruby_request *request, ruby_result *result) {
  memset(result, 0, sizeof(*result));
  guest_state state = {.request = request, .result = result};
  active_state = &state;
  mrb_state *mrb = mrb_open();
  if (!mrb) { result->status = 2; snprintf(result->error, sizeof(result->error), "mruby initialization failed"); return; }
  mrb->ud = &state;
  mrb_bool failed = FALSE;
  mrb_value exception = mrb_protect_error(mrb, run, &state, &failed);
  if (failed) {
    if (!result->status) result->status = 2;
    snprintf(result->error, sizeof(result->error), "Ruby execution failed");
    state.exception = exception;
    mrb_gc_register(mrb, exception);
    mrb_bool presentation_failed = FALSE;
    mrb_protect_error(mrb, error_details, &state, &presentation_failed);
  }
  mrb_close(mrb);
  active_state = NULL;
}

void ruby_result_free(ruby_result *result) { free(result->json); result->json = NULL; }
