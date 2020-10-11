module trainings; 

export {
	redef enum Notice::Type += {
		Local, 
		Remote, 
	}; 
} 

redef Site::local_nets+= { 192.168.86.0/24} ; 

event new_connection(c: connection)
    {
	print fmt ("%s, %s", c$uid, c$id); 

	local orig=c$id$orig_h ; 
	local resp=c$id$resp_h ; 
	local service=c$id$resp_p ; 

	local _msg = fmt ("connection on %s seen", service); 

	if (orig in Site::local_nets) { 
		 NOTICE([$note=Local, $conn=c, $identifier=cat(orig), $suppress_for=1 hrs, $msg=_msg]);
	}
	else 
		 NOTICE([$note=Remote, $conn=c, $identifier=cat(orig), $suppress_for=1 hrs, $msg=_msg]);
    } 


hook Notice::policy(n: Notice::Info)
    {
        if ( n$note == trainings::Local && n$src in Site::local_nets)
                add n$actions[Notice::ACTION_EMAIL];
	else 	
                add n$actions[Notice::ACTION_LOG];
    }
