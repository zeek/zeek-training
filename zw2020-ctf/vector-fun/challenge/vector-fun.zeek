# Set your guess and run the script to see if you guessed correctly.

global your_guess: string = "" &redef;

global v: vector of any = {"Kjjm=", 8, "VGhl", -1, "0lz", "HbL", "Rs==", 9, "VGhpc", "ZzIy", 3, 12, "2Jc", "Mw==", "Rmxh", function(): count { return 13; }, "kr1", 14};
your_guess = encode_base64(your_guess);
if (your_guess[20:24] == (v[(v[15] as function(): count)()] as string)) { if (your_guess[5:8] == (v[4] as string)) { if (your_guess[12:16] == (v[(v[(v[3] as int):][0] as count)] as string)) { if (your_guess[16:20] == (v[(v[7] as count)] as string)) { if (your_guess[0:5] == (v[(v[1] as count)] as string)) { if (your_guess[8:12] == (v[(10 - (v[1] as count))] as string)) {
  print "your guess was right!";
}}}}}}


