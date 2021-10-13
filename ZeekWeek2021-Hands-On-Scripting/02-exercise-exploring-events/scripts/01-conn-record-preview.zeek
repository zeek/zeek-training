module training;

event new_connection(c: connection)
{
	print fmt ("");
	print fmt ("");
	print fmt ("%s", c) ;
}


event zeek_done()
{

	print fmt ("");
	print fmt ("");
	print fmt ("Run as: zeek -r Traces/01-conn-record-preview.pcap scripts/01-conn-record-preview.zeek");
	print fmt ("======================================================================================");
	print fmt ("The above is dump of internal data structure of a connection record");
	print fmt ("which is being tracked by zeek at any given point in tcp state-machine");
	print fmt ("you'd see a lot of uninitialized members of connection record which");
	print fmt ("may or may not setup as bytes for this connection progress");
	print fmt ("this is pretty much the data which eventually is seen in conn.log");
	print fmt ("Useful tip: get yourself familarize with different kinds of conn events");
	print fmt ("eg. new_connection, connection_established, connection_state_remove etc");
	print fmt ("=====================================================================================");
	print fmt ("");
	print fmt ("");
}
