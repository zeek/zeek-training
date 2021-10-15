# This script generated the SSH traffic in the challenge pcap

for i in {0..98}
do
  echo ${i}
  sleep ".$((1 + RANDOM % 10))"
  scp -q -4 -l 1000 -r localhost:/usr/lib ./data &
done

# while this script is going, manually SSH to localhost and type things
