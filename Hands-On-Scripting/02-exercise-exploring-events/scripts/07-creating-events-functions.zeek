module training;

export {

        global my_event: event(ip: addr, p: port);
        global my_function: function(p: port): string ;
}

function my_function(p: port): string
    {
    if (p == 22/tcp)
        return "ssh" ;

    return "unknown" ;
    }

event training::my_event(ip: addr, p: port)
    {

    local service_name = my_function(p);

    print fmt ("") ;
    print fmt ("") ;
    print fmt ("event my_event says: A connection was made to: %s on %s", ip, service_name);
    }

event connection_established(c: connection)
    {
	if (c$id$orig_h == 192.168.86.92)
	{
        print fmt ("") ;
        print fmt ("") ;


		print fmt("event connection_established says: Found a ssh connection: %s", c$id);

        # firing our custom created event now
        # note: try a run after removing training::

        event training::my_event(c$id$resp_h, c$id$resp_p);
	}
    }

event zeek_done()
    {
        print fmt ("") ;
        print fmt ("") ;
        print fmt ("") ;
        print fmt ("================================================================================");
        print fmt ("Run as: zeek -r Traces/07-creating-events-functions.pcap 07-creating-events-functions.zeek");
        print fmt ("================================================================================");
    }

