# What looks like it could be morse code definitely is not

global morse_code: table[int] of string = {
  [0] = "........... __     __        ___          _____  _\__\___\____\_ __                  ",
  [1] = "\\__    \_\__/////././././././//////././././|  |__ |__| __\___|   | _\__\_\__ ////././././././//.///  _  \\ \\_   _____/././././././/|  | _____     ____  ",
  [2] = "  \| \  \ | \  |\  |  \\|  |/./././././  ___/////   |/./  ___/././ \/ //_\\  \\ |    __)  |  | \\__  \\   //// ___\\ ",
  [3] = "  |    |   |   Y  \\  |\\___ \\|   |\\___ \\/././././././//    |    \\|     \\   |  |__/./././ __ \\_/ //_/////././/  >",
  [4] = " \ |____|   |___|  \//__/./____  >_\__/././_\__\_  >_\___|__  //\\__\_  //   |____(____  //\\_\_\_  // ",
  [5] = "  \  \ \  \ \ \       \\/./        \\/./ \ \   \    \\/././     \   \\/     \\/./././              \\//./////./ \/_____/  ",
};

local v: vector of string = vector();
for (idx in morse_code) {
  v[idx] = morse_code[idx];
}

# print the strings and you get garbage
for (idx in v) {
  print idx, v[idx];
}

# compress the paths and the flag appears
for (idx in v) {
  print compress_path(v[idx]);
}
