import itertools
import random
import sys
import broker

alphabet = 'abcdefghijklmnopqrstuVwxyZ'
flag_length = 4
flag_choice = random.choice(range( len(alphabet)**flag_length ))
print(flag_choice)
iterations = 0

ep = broker.Endpoint()
sub = ep.make_subscriber("/topic/test")
ss = ep.make_status_subscriber(True);
ep.peer("127.0.0.1", 9999)
st = ss.get()

if not (type(st) == broker.Status and st.code() == broker.SC.PeerAdded):
  print("could not connect")
  sys.exit(0)

def make_dem_chars(l):
   yield from itertools.product(*([l] * flag_length))

for char in make_dem_chars(alphabet):
  flag = ''.join(char)
  if iterations == flag_choice:
    print(flag)
    add_to_bloom_event = broker.zeek.Event("add_flag", flag);
    ep.publish("/topic/test", add_to_bloom_event);
    with open('flag.txt', 'w') as f:
      f.write(flag)
  iterations += 1

print("done")
