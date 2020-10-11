module trainings; 

redef exit_only_after_terminate=T ; 

redef Site::local_nets+= { 192.168.86.0/24} ; 

export {
	redef enum Notice::Type += {
		Local, 
		Remote, 
	}; 

	option false_positives: set[addr] = {}  ; 
	redef Config::config_files += { fmt("%s/false-positive.file",@DIR) };
} 


event new_connection(c: connection)
    {
	print fmt ("%s, %s, %s", c$uid, c$id, Config::config_files ); 

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
        if ( n$note == trainings::Local && n$src in Site::local_nets && n$src !in trainings::false_positives )
                add n$actions[Notice::ACTION_EMAIL];
	else 	
                add n$actions[Notice::ACTION_LOG];
                                    }

event zeek_done()
    {
	print fmt ("%s", trainings::false_positives) ; 
    } 
