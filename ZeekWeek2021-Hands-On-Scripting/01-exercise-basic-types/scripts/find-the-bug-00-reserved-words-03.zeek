module training;

global ip = 1.1.1.1 ; 

event zeek_init()
{
	local port = 22/uknown; 
	print fmt ("IP: %s connected on port: %s", ip, port); 
} 

event zeek_done()
{
	print fmt (""); 
	print fmt (""); 
	print fmt ("===================================================="); 
	print fmt ("don't let unknowns confuse you"); 
	print fmt ("1. There is a reserved keyword bug in the code"); 
	print fmt ("===================================================="); 
} 

