module trainings; 

redef Site::local_nets+= { 192.168.86.0/24} ; 

event connection_state_remove(c: connection)
{

	print fmt ("%s", c$conn); 

	local orig=c$id$orig_h ; 
	local resp=c$id$resp_h ; 
	local dst_port =c$id$resp_p ; 
	local service =c$conn$service ;
	local conn_state = c$conn$conn_state; 
	
	if (orig in Site::local_nets) 
		print fmt("%s attempted a %s connection to %s on port %s", orig, service, resp, dst_port); 
}

