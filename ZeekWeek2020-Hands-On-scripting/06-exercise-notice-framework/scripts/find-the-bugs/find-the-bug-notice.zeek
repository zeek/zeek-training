module trainings; 

export {
	redef enum Notice::Type += {
		Seen, 
	}; 
} 

event new_connection(c: connection)
{ 
	#print fmt ("%s", c); 
}

redef Site::local_nets+= { 192.168.86.0/24} ; 

event connection_established(c: connection)
{

	print fmt ("%s, %s", c$uid, c$id); 

	local orig=c$id$orig_h ; 
	local resp=c$id$resp_h ; 
	local service=c$id$resp_p ; 

	if (orig in Site::local_nets) 
	{ 
		local msg = fmt ("connection on %s seen", service); 
		 NOTICE([$note=Seen, $conn=c, $identifier=cat(orig), $suppress_for=1 hrs, $msg=_msg]);
	}
} 

