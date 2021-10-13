module training;

export {

global ip: set[addr] = {1.1.1.1, 2.1.1.2, } &redef;
global net:set[subnet] = { 1.1.1.0/24, } ;

}

event zeek_init()
{
	if (ip in net)
	{
		print fmt("%s is in subnet %s", ip, net);
	}
}



