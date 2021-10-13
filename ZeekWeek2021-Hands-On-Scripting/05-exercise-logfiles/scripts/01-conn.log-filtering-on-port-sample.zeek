module training;

# we are using configuration framework to read the list of filtered ports
# into a set called filtered_ports

export {
    option filtered_ports: set[port] = {} ;
    redef Config::config_files += { fmt("%s/filtered-ports.file",@DIR) };
}

# just some usable messages
event zeek_init()
    {
	print fmt ("to see filtering in conn.log" );
	print fmt ("try zeek -i eth0 01-conn.log-filtering-on-port-sample.zeek");
	print fmt ("then look at conn.log");
	print fmt ("");
    }

# This is where log filtering can happen based on criteria you setup

hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
{

    local dport = rec$id$resp_p ;
    if (dport !in filtered_ports)
		break ;
}

## OLD Stuff: how it used to be in the past !

#function ignore_logging (rec: Conn::Info) : bool
#    {
#    # Record only connections with successfully analyzed HTTP traffic
#    local dport = rec$id$resp_p ;
#
#    return (dport in filtered_ports) ? T : F ;
#    }

#event zeek_init()
#    {
#
#    local filter: Log::Filter = [$name="filter54", $path="conn", $pred=ignore_logging];
#    Log::remove_filter(Conn::LOG, "default");
#    Log::add_filter(Conn::LOG, filter);
#    }

