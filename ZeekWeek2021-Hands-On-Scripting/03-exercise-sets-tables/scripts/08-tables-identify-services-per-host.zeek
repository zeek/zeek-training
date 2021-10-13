module training;

redef exit_only_after_terminate = T ;

global host_profiles: table [addr] of set[port] ;

event connection_established (c: connection)
{

	local orig=c$id$orig_h ;
	local resp=c$id$resp_h ;
	local service=c$id$resp_p ;

	#if (resp !in Site::local_nets)
	#	return ;


	if ([resp] !in host_profiles)
	{
		host_profiles[resp]=set();
	}

	if (service !in host_profiles[resp])
		add host_profiles[resp][service] ;

}


event zeek_done()
{
	local iplist = "" ;
	local msg = "" ;

	for (h in host_profiles)
	{
		for (p in host_profiles[h])
			{ msg += fmt ("%s ", p); }

			print fmt ("host: %s is listening on  %s", h, msg);
	}


	print fmt ("");
	print fmt ("##############################");
	print fmt ("");
	print fmt ("btw, Did you look at http.log yet ?" ) ;
	print fmt ("##############################");
	print fmt ("");

}
