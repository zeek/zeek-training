module training;

global services: set[port] ;
global remote_ips: set[addr];


event new_connection(c: connection)
{

	local orig=c$id$orig_h ;
	local resp=c$id$resp_h ;
	local service=c$id$resp_p ;


	if (service !in services)
		add services[service] ;


	if (orig !in remote_hosts)
		add remote_hosts[orig] ;

}


event zeek_done()
{

	print fmt ("uniq services seen");
	for (service in services)
		print fmt ("%s ", service) ;

	print fmt ("Uniq remote IPs seen");
	for (ip in remote_hosts)
		print fmt ("%s", ip) ;

}
