# run_cmd: zeek -C -r pcaps/ssh-over-443.pcap  policy/frameworks/dpd/detect-protocols.zeek 


export {

	global expire_notice_escalation: function(t: table[addr] of set[string], idx: addr): interval ; 

	global notice_escalation: table[addr] of set[string] &create_expire=10 secs &expire_func=expire_notice_escalation ; 

} 


function expire_notice_escalation (t: table[addr] of set[string], idx: addr): interval 
{ 
	print fmt ("%s", t); 

	return 0 secs; 
} 

hook Notice::policy(n: Notice::Info)
{
        if ( n$src !in notice_escalation) 
	{ 	
		local aset = set[string] = {} ; 
		notice_escalation[n$src]=aset ; 
	} 
                
	add notice_escalation[n$src] [n$type] ; 


	if (|notice_escalation[n$src] >1) 
		print ("we got more notices: %s", notice_escalation[n$src]); 
        
}


event zeek_done()
{
	print fmt ("%s", notice_escalation); 
} 




#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi policies/ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ zeek -r pcaps/ssh-over-443.pcap  policies/ex-4-many-notices.zeek
#error in ./policies/ex-4-many-notices.zeek, line 24: syntax error, at or near "["
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ cp policies/ex-4-many-notices.zeek policies/find-the-bug-ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi policies/ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ zeek -r pcaps/ssh-over-443.pcap  policies/ex-4-many-notices.zeek
#error in ./policies/ex-4-many-notices.zeek, line 28: syntax error, at or near "type"
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi policies/ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ zeek -r pcaps/ssh-over-443.pcap  policies/ex-4-many-notices.zeek
#error in string and ./policies/ex-4-many-notices.zeek, line 28: type clash (string and n$note)
#error in ./policies/ex-4-many-notices.zeek, line 28 and string: type mismatch (n$note and string)
#error in ./policies/ex-4-many-notices.zeek, line 28: expression with type 'table' is not a type that can be indexed (notice_escalation[n$src][n$note])
#error in ./policies/ex-4-many-notices.zeek, line 31: operands must be of the same type (1 < notice_escalation[n$src])
#error in ./policies/ex-4-many-notices.zeek, line 31: syntax error, at or near ")"
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ less ~/zeek/share/zeek/base/frameworks/notice/main.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi policies/ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ less ~/zeek/share/zeek/base/frameworks/notice/main.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ zeek -r pcaps/ssh-over-443.pcap  policies/ex-4-many-notices.zeek
#error in ./policies/ex-4-many-notices.zeek, line 25: type clash in assignment (notice_escalation[n$src] = aset)
#error in ./policies/ex-4-many-notices.zeek, line 31: operands must be of the same type (1 < notice_escalation[n$src])
#error in ./policies/ex-4-many-notices.zeek, line 31: syntax error, at or near ")"
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi
#conn.log           notice.log         packet_filter.log  pcaps/             policies/          questions          ssh.log
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi policies/ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ zeek -r pcaps/ssh-over-443.pcap  policies/ex-4-many-notices.zeek
#error in ./policies/ex-4-many-notices.zeek, line 31: operands must be of the same type (1 < notice_escalation[n$src])
#error in ./policies/ex-4-many-notices.zeek, line 31: syntax error, at or near ")"
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi policies/ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ zeek -r pcaps/ssh-over-443.pcap  policies/ex-4-many-notices.zeek
#error in ./policies/ex-4-many-notices.zeek, line 32: syntax error, at or near ","
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi policies/ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ zeek -r pcaps/ssh-over-443.pcap  policies/ex-4-many-notices.zeek
#{\x0a\x0a}


#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ zeek -r pcaps/ssh-over-443.pcap  policies/ex-4-many-notices.zeek
#{\x0a\x0a}
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi policies/find-the-bug-ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi policies/ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ zeek -r pcaps/ssh-over-443.pcap  policies/ex-4-many-notices.zeek
#1601870248.874184 error in <no location> and ./policies/ex-4-many-notices.zeek, line 25: index type doesn't match table (ProtocolDetector::Protocol_Found and list of any)
#1601870248.874184 error in <no location> and ./policies/ex-4-many-notices.zeek, line 25: index type doesn't match table (ProtocolDetector::Server_Found and list of any)
#{\x0a\x09[147.161.166.157] = {\x0a\x0a\x09},\x0a\x09[162.241.219.40] = {\x0a\x0a\x09}\x0a}
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ vi policies/ex-4-many-notices.zeek
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ zeek -r pcaps/ssh-over-443.pcap  policies/ex-4-many-notices.zeek
#{\x0a\x09[147.161.166.157] = {\x0a\x09\x09ProtocolDetector::Protocol_Found\x0a\x09},\x0a\x09[162.241.219.40] = {\x0a\x09\x09ProtocolDetector::Server_Found\x0a\x09}\x0a}
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$ cat notice.log
##separator \x09
##set_separator  ,
##empty_field    (empty)
##unset_field    -
##path   notice
##open   2020-10-06-18-10-40
##fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type  file_desc       proto   note    msg     sub     src     dst     p       n       peer_descr      actions suppress_for    remote_location.country_code    remote_location.region  remote_location.city  remote_location.latitude remote_location.longitude
##types  time    string  addr    port    addr    port    string  string  string  enum    enum    string  string  addr    addr    port    count   string  set[enum]       interval        string  string  string  double  double
#1601870248.874184       CX6W3lvmY3Sle7Mxg       147.161.166.157 65301   162.241.219.40  443     -       -       -       tcp     ProtocolDetector::Protocol_Found        147.161.166.157:65301 > 162.241.219.40:443 SSH on port 443/tcp  SSH     147.161.166.157 162.241.219.40  443     -       -       Notice::ACTION_LOG     3600.000000     -       -       -       -       -
#1601870248.874184       CX6W3lvmY3Sle7Mxg       147.161.166.157 65301   162.241.219.40  443     -       -       -       tcp     ProtocolDetector::Server_Found  162.241.219.40: SSH server on port 443/tcp      SSH     162.241.219.40  162.241.219.40  443     -       -       Notice::ACTION_LOG      3600.000000   --       -       -       -
##close  2020-10-06-18-10-40
#[bro@adhoc /usr/local/bro-cpp/adhoc-master/host/policies/zeek-scripting-training/exercise-notice]$
#
#
