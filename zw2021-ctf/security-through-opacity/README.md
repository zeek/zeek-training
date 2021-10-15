Security Through Opacity
========================

Zeek has some interesting datatypes which are refered to as opaque types. They include topk, hyperloglog, and bloomfilter structures.
This challenge is about bloomfilters.

1. I ran `zeek flags-to-bloom.zeek` which started a broker listener and waited to receive events name `add_flag` on topic `/topic/test.`.
2. I ran `make_flags.py` which generated all possible strings consisting of lowercase values with length 4, randomly selected one, and sent it to the zeek process. The zeek process handled the `add_flag` event and added the string to a bloomfilter.
3. The flags-to-bloom script printed 2 lines of output. One line was the string "flag added" the other is the serialized version of the bloomfilter containing only 1 string, the flag. Output was piped to a file named `bloom`.

See if you can recover the original value of the flag which was added to the bloomfilter.

