module Notice;
#hook notice(n: Notice::Info) &priority=1
#{
#
#	if (n?$src)
#	{
#		DNS::hot_subnet_check(n$src);
#	}
#
#}
