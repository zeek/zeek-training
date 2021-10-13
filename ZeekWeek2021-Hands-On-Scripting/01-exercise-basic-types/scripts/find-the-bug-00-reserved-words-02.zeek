module training;

global ip = 1.1.1.1;

event zeek_init()
{
	local port = 22/tcp ;
	print fmt ("IP: %s connected on port: %s", port);
}

event zeek_done()
{
	print fmt ("");
	print fmt ("");
	print fmt ("====================================================");
	print fmt ("this version has two bugs");
	print fmt ("1. There is a reserved keyword bug in the code");
	print fmt ("2. second bug is because I forgot something, oops!");
	print fmt ("====================================================");
}

