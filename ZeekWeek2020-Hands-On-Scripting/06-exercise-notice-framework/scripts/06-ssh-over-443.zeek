# run_cmd: zeek -C -r Traces/ssh-over-443.pcap  policy/frameworks/dpd/detect-protocols.zeek 

@load policy/frameworks/dpd/detect-protocols.zeek 

event zeek_init()
    {
	print fmt ("look into notice.log"); 
	print fmt (""); 
	print fmt (""); 
	print fmt ("========================="); 
    } 

hook Notice::policy(n: Notice::Info)
    {
        if ( n$note == ProtocolDetector::Server_Found && /SSH/ in n$msg && (n$id$resp_p == 443/tcp || n$id$resp_p == 7070/tcp || n$id$resp_p == 8080/tcp) ) {
                add n$actions[Notice::ACTION_EMAIL];
        }
    }

