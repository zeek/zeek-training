module training;

local ip = 1.1.1.1;
local sport = 22/tcp;
local ssub = 1.1.1.0/24 ;
local answer = F;

event zeek_init()
{
	if (ip in ssub)
	{
		answer= T;
	}
}

event zeek_done()
{

	print fmt("Answer that %s is in %s: %s", ip, ssub, answer);
}


# you see error because local vars must be decleared inside the scope of
# an event or a function.

#local - scope of a local variable starts at the location where it is declared and persists to the end of the function, hook, or event handler in which it is declared. All variables in functions need to be declared with local keyword (except using “const” or in a for loop)


#If a global identifier is declared after a “module” declaration, then its scope ends at the end of the current Zeek script or at the next “module” declaration, whichever comes first.


#If a global identifier is declared after a “module” declaration, but inside an export block, then its scope ends at the end of the last loaded Zeek script, but it must be referenced using the namespace operator (::) in other modules.


