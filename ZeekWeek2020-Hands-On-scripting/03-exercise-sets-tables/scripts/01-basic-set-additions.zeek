module training;
global services: set[port] ;
global remote_hosts: set[addr];

event zeek_init()
{
	print fmt (""); 
	print fmt (""); 
	print fmt ("In this exercise we have following two sets"); 
	print fmt ("1. services: set of ports");
	print fmt ("2. remote_hosts: set of ipaddresses"); 
	print fmt ("In both sets we store incoming IPs and dst ports"); 
	print fmt ("since sets only store uniq values, multiple additions"); 
	print fmt ("are simply overwritten. One can infact otherwise do a"); 
	print fmt ("memebership test before adding as seen in the script"); 
	print fmt (""); 
	print fmt (""); 
	print fmt (""); 
} 

event new_connection(c: connection)
{

        local orig=c$id$orig_h ;
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
