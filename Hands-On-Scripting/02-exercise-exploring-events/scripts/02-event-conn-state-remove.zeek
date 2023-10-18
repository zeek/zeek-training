module training;

event connection_state_remove(c: connection)
{
	print fmt ("%s", c) ;
}

event zeek_init()
{

	print "" ;
	print "" ;
	print fmt ("Run as: zeek -r Traces/02-event-conn-state-remove.pcap scripts/02-event-conn-state-remove.zeek");
	print "" ;
	print "########################################################################" ;
	print fmt ("If you compare connection record from 01-conn-record-preview.zeek");
	print fmt ("you'll notice that this exercise's connection record is a lot more");
	print fmt ("complete. Look at \"ssh=[\" on 10th line onwards in the output" );
	print fmt ("The reason being 01-conn-record-preview.zeek taps into");
	print fmt ("event new_connection ie very early in TCP connection setup");
	print fmt ("where as this record is dumped in event connection_state_remove");
	print fmt ("which is an event which zeek executes when flushing entire connection");
	print fmt ("memory");
	print "########################################################################" ;
	print "" ;
	print "" ;
}


