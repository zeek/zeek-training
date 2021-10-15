
event zeek_init() {
  for (m,v in global_ids()) {
    if ("lambda" in m) {
      local func_body: string = split_string1(fmt("%s", v$value), />/)[1];
      if (sha256_hash(func_body) == "08bf9fc732ea7ad84653bc44714a34b3d9a07f1bdf4daf13c592715c25ec84c6") {
        local f: function(n: count): string = v$value;
        print f(5);
      }
    }
  }
}
