module training;

event new_connection(c: connection)
{
	print ("---------------------------");
	print fmt ("new_connection: orig: %s", c$orig);
	print fmt ("new_connection: resp: %s", c$resp);
}
event connection_established(c: connection)
{
	print ("");
	print fmt ("connection_established: orig: %s", c$orig);
	print fmt ("connection_established: resp: %s", c$resp);
	print ("---------------------------");
}
event connection_state_remove(c: connection)
{
	print ("");
	print fmt ("connection_state_remove: orig: %s", c$orig);
	print fmt ("connection_state_remove: resp: %s", c$resp);
	print ("---------------------------");
}


event zeek_init()
{

	print fmt ("");
	print fmt ("Run as: zeek -r Traces/03-events-across-tcp-connection.pcap scripts/03-events-across-tcp-connection.zeek");
	print fmt ("");
	print fmt ("##############################################################");
	print fmt ("This exercise demonstrates different stages of zeek processing");
	print fmt ("the tcp connection.");
	print fmt ("First:  event new_connection");
	print fmt ("Second: event connection_established");
	print fmt ("Third:  event connection_state_remove");
	print fmt ("");
	print fmt ("Notice: the \"num_bytes_ip\" differ at different stage of processing");
	print fmt ("###############################################################");
	print fmt ("");
}
