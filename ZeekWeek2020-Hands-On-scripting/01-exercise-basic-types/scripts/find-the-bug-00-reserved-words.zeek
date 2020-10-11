module trainings;

global ip = 1.1.1.1; 

event zeek_init()
    {
        local port = 22/tcp; 

        print fmt ("IP: %s connected on port: %s", ip, port); 
    } 

event zeek_done()
    {
	print fmt (""); 
	print fmt (""); 
	print fmt ("============================================"); 
	print fmt ("There is a reserved keyword bug in the code"); 
	print fmt ("============================================"); 
    } 

