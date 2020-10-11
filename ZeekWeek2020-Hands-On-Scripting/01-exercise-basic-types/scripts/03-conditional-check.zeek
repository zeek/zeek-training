module trainings;

export { 
	global ip: set[addr] = {1.1.1.1, 1.1.1.2} &redef; 
	global sport= 22/tcp ; 
	global net:set[subnet] = {1.1.1.0/24} ; 
	global answer: bool = F; 
} 

event zeek_init()
    {
        if (sport < 1024/tcp )
            print fmt ("%s is in well-known ports", sport); 

        if (1.1.1.1 in ip) 
		    print ("1.1.1.1 is in set of ips"); 

    } 

event zeek_done()
    {
	print fmt ("==========================================================="); 
	print fmt ("nothing significant to show except how conditional checks"); 
	print fmt ("are done as well as how built-in network centric datatypes"); 
	print fmt ("can be used effortlessly"); 
	print fmt ("==========================================================="); 
    } 
