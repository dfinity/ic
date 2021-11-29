#include <stdio.h>


static char *itohexa_helper(char *dest, unsigned x) {
  if (x >= 16) {
    dest = itohexa_helper(dest, x/16);
  }
  *dest++ = "0123456789ABCDEF"[x & 15];
  return dest;
}

char *itohexa(char *dest, unsigned x) {
  *itohexa_helper(dest, x) = '\0';
  return dest;
}



#define WASM_IMPORT(m,n) __attribute__((import_module(m))) __attribute__((import_name(n)));
#define WASM_EXPORT(n) asm(n) __attribute__((visibility("default")))

int dfn_ads(void) WASM_IMPORT("ic0", "msg_arg_data_size");
void dfn_adc(void *, int, int) WASM_IMPORT("ic0", "msg_arg_data_copy");
void dfn_reply_append(void *, int) WASM_IMPORT("ic0", "msg_reply_data_append");
void dfn_reply(void) WASM_IMPORT("ic0", "msg_reply");
void dfn_print(void *, int) WASM_IMPORT("ic0", "debug_print");

void compute() WASM_EXPORT("canister_query compute");
void compute() {
  char buf[128];
  int sz = dfn_ads();
  dfn_adc(buf, 0, sz);
  
  // Encoded string: "DIDL" 0 1 0x71 LEB128(length) data
  // So offset 7 holds string length (for short strings).
  int result = main();
  itohexa(buf+8, result);
  buf[5] = 1;
  buf[6] = 0x71;
  buf[7] = 8;
  dfn_print(buf+7, 8);
  dfn_reply_append(buf, sz + 10);
  dfn_reply();
}
