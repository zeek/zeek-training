# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

module training;

# TODO: you see error because local vars must be decleared inside the scope of
# an event or a function.
local ip = 1.1.1.1;
local sport = 22/tcp;
local ssub = 1.1.1.0/24;
local answer = F;

event zeek_init()
	{
	if ( ip in ssub )
		{
		answer = T;
		}
	}

event zeek_done()
	{
	print fmt("Answer that %s is in %s: %s", ip, ssub, answer);
	}
