# @TEST-EXEC: zeek %INPUT >output
# @TEST-EXEC: btest-diff output

module training;

global ip = 1.1.1.1;

event zeek_init()
	{
	# TODO: There is a reserved keyword bug in the code.
	local port = 22/tcp;
	print fmt("IP: %s connected on port: %s", ip, port);
	}
