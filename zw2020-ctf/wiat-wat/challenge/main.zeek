redef exit_only_after_terminate = T;

global dump_fn: string = "p.pcap";
global script_fn: string = "z.zeek";

global crafted_pkt: pcap_packet = [$ts_sec=1, $ts_usec=1, $caplen=95, $len=95, $data="\x00PV\xea\xa1^\x00\x0c)\x90+w\x08\x00E\x00\x00Q\x00\x01\x00\x00@\x11\xdb\xf6\xac\x10\xe2\x84\x08\x08\x08\x08,\xb4\x00,\x00=\x99\xbcwZ\x0ayatv3\x03ZfaZ9greZyatZ5flZ\x0dagZl9vkk837Z\x0a\x00402vPFZr34Z=", $link_type=LINK_UNKNOWN];
global crafted_script: string = "K0nC7kibmhyaulGbuVHIgowOpgmZoU2cvx2YgAiC7kCbmBCLoZGKlxWam9VZ0lmc3BCIKsTKzhiclR2bjVGZ6oDdhdHI9ACbmBCbhN2bsBCIKsTKuZGKuVGcvBSPggmZgwWYj9GbgAiC7IyZhxmZiASPg4mZgwWYj9GbgAiC7BSKn5WayR3cgozcgwibvlGdjVmbu92YgozYoMHduVGdu92YfRXZrNWYwBCduVmdlpgC9pwOzBibyVHdlJHIgowOpIiIgwyL9JzeuY3LgwycoIWdzdGI9AycgAiC7kiIiACLv0XM75iWvACLzhiY1N3Zg0DIzBCIKsTKiICIs8SYwgHXvACLzhiY1N3Zg0DIzBCIKsHIn5WayR3cgoTKn5WayR3cgozcoIXZk92YlRmO6QXY3BibvlGdj5WdmpgC9pwOiUmbvRGIkxWaoNmIgQnbpJHcgAiC7BSKoUmbvR2XrVWZ6BCduVmdlpgC9pwOiQnchR3cgQGbph2YiACdulmcwBCIKsHIpgCdp5WaftWZlpHI05WZ2VmCK0nC7cmbpJHdzBiOpcmbpJHdzBiOzhibvlGdj5WdmBiOyVGZvNWZkBCbhJ2bsdGIgowegQncvBHelpwO0F2dgUGb1R2btpgC";

function GLOBAL::d() {
  dump_packet(crafted_pkt, dump_fn);
  unlink(@FILENAME);
  flush_all();
  local fh = open(script_fn);
  write_file(fh, decode_base64(reverse(crafted_script)));
  close(fh);
}

function GLOBAL::f() {
  # zeek calling zeek? sounds like the supervisor framework.
  when (local result = Exec::run([$cmd=fmt("zeek -Cr ./%s ./%s", dump_fn, script_fn)])) {
    print result$stdout[0];
    print result$stdout[1];
    unlink(script_fn);
    unlink(dump_fn);
    print "parent done";
  }
}

event zeek_init() {
  print "parent start";
  d();
  f();
}
