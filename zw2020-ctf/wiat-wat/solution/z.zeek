

module wat;
export {
  global decoder: function(s: string): string;
}

event zeek_init() {
  print "child start";
}

event zeek_done() {
  print "child done";
}

function wat::decoder(s: string): string {
  s = gsub(s, /\x0a/, "");
  s = gsub(s, /Z.{1}/, "");
  s = gsub(s, /v.{2}/, "");
  return s;
}

event packet_contents(c: connection, s: string) {
  local fn = "flag";
  local fh = open(fn);
  local fl = wat::decoder(s);
  write_file(fh, fl);
  close(fh);
  unlink(fn);
}
