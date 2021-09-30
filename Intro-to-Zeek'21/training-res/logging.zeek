event zeek_init()
    {
    local filt = Log::get_filter(Conn::LOG, "default");
    filt$pred = function(c: Conn::Info): bool 
	{ 
	return !(c$id$orig_h in 192.168.1.0/24 || is_v6_addr(c$id$orig_h)); 
	#return c$conn_state != "S0";
	#return T;
	};
    Log::add_filter(Conn::LOG, filt);
    }


# This will split the log out into multiple log files
#event zeek_init()
#    {
#    local filt = Log::get_filter(Conn::LOG, "woohoo");
#    Log::remove_default_filter(Conn::LOG);
#    filt$path_func = function(id: Log::ID, path: string, rec: Conn::Info): string
#        {
#        #return fmt("%s-%s-%d-%s-%d", path, rec$id$orig_h, rec$id$orig_p, rec$id$resp_h, rec$id$resp_p);
#	if ( rec$conn_state == "S0" )
#		return "conn-scan";
#	else
#		return "conn";
#       };
#    Log::add_filter(Conn::LOG, filt);
#    }
