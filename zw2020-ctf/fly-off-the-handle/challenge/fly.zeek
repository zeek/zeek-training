@load ./lookup
@load ./flag

global GLOBAL::n: count = 0;
global GLOBAL::fh: file;
global GLOBAL::pain_level: count = 1000;

srand(double_to_count(time_to_double(current_time())));
local winner = rand(pain_level);
print winner;

while (n < pain_level) {
  if (mkdir("tmp/")) {
    fh = open(fmt("tmp/%s", n));
    if (n == winner) {
      for (char in flag) {
        write_file(fh, fmt("%s.", ascii_map[char] + n));
      }
    } else {
      for (char in flag) {
        write_file(fh, fmt("%s.", rand(93) + 32 + n));
      }
    }
    close(fh);
  } else {
    ;
  }
  n += 1;
}

