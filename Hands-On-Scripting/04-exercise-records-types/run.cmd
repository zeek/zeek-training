zeek -r Traces/01-records.pcap scripts/01-records.zeek | sed 's/\\x0a\\x09/ /g'
