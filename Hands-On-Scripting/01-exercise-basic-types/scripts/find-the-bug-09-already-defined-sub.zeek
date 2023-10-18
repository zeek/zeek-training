module training;

global ip = 1.1.1.1;

event zeek_init()
{

	local sub = 1.1.1.0/24 ;
	if (ip in sub)
	{
		print fmt("Answer: %s is in %s", ip, sub);
	}
}

