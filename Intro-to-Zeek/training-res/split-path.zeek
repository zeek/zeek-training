function myfunc(id: Log::ID, path: string, rec: HTTP::Info) : string
   {
    local r = Site::is_local_addr(rec$id$resp_h) ? "local" : "remote";
    return fmt("%s-%s", path, r);
   }
event zeek_init()
   {
    Log::remove_filter(HTTP::LOG, "default");
    local filter: Log::Filter = [$name="http-split",
        $path_func=myfunc];
    Log::add_filter(HTTP::LOG, filter);
   }


