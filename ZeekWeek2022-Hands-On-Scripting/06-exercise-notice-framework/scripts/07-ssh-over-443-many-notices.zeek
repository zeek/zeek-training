# run_cmd: zeek -C -r pcaps/ssh-over-443.pcap  policy/frameworks/dpd/detect-protocols.zeek 

@load policy/frameworks/dpd/detect-protocols.zeek

export {

	global expire_notice_escalation: function(t: table[addr] of set[Notice::Type], idx: addr): interval ; 

	global notice_escalation: table[addr] of set[Notice::Type] &create_expire=10 secs &expire_func=expire_notice_escalation ; 

} 

event zeek_init()
    {
        print fmt ("look into notice.log");
        print fmt ("");
        print fmt ("");
        print fmt ("=========================");
    }


function expire_notice_escalation (t: table[addr] of set[Notice::Type], idx: addr): interval 
    { 
	print fmt ("%s", t); 

	return 0 secs; 
    } 

hook Notice::policy(n: Notice::Info)
    {
	local ip=n$id$orig_h ; 
	#local ip=n$src ;  // determine why is that wrong :) 

    if ( ip !in notice_escalation) { 	
		local aset: set[Notice::Type] ; 
		notice_escalation[ip]=aset ; 
	} 
                
	add notice_escalation[ip] [n$note] ; 

	if (|notice_escalation[ip]| >1) 
		print fmt ("we got more notices: %s", notice_escalation[ip]); 
        
    }


event zeek_done()
    {
	print fmt ("%s", notice_escalation); 
    } 
