module trainings; 

export {
    option filtered_ports: set[port] = {} ; 
    redef Config::config_files += { fmt("%s/filtered-ports.file",@DIR) };
} 

event zeek_init()
{
	print fmt ("to see filtering in conn.log" ); 
	print fmt ("try zeek -i eth0 01-conn.log-filtering-on-port-sample.zeek"); 
	print fmt ("then look at conn.log"); 
	print fmt (""); 
} 
function ignore_logging (rec: Conn::Info) : bool
    {
    # Record only connections with successfully analyzed HTTP traffic
    local dport = rec$id$resp_p ; 

    return (dport in filtered_ports) ? T : F ;
    }

event zeek_init()
    {

    local filter: Log::Filter = [$name="filter54", $path="conn", $pred=ignore_logging];
    Log::remove_filter(Conn::LOG, "default");
    Log::add_filter(Conn::LOG, filter);
    }

