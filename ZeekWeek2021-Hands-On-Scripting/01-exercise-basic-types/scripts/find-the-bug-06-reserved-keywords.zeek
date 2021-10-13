module training;

global ip = 1.1.1.1;
global sub = 1.1.1.0/24 ;
global answer: bool = F;

event zeek_init()
{
	local port = 22/tcp;

	if (ip in sub)
	{
		answer= T;
	}


}

event zeek_done()
{
	print fmt("Answer that %s is in %s: %s", ip, sub, answer);


	print fmt ("");
	print fmt ("");
	print fmt ("============================================");
	print fmt ("There are two bugs in the code");
	print fmt ("both are related to reserved keywords");
	print fmt ("Yes, you'd be somewhat surprised on the second one");
	print fmt ("============================================");
}

