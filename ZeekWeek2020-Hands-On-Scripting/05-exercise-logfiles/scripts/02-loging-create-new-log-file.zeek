module training; 

redef exit_only_after_terminate=T ; 

export {

	redef enum Log::ID += { conn_summary_LOG } ; 

	type conn_info: record {
		start_time : time &log; 
		end_time: time &log; 
		hosts: set[addr] ;
		host_count: count &default=0 &log ;
		conn_count: count &default=0 &log; 
	} ; 


	global expire_summary : function ( t: table[addr] of conn_info, idx: addr): interval ; 
	global summary: table[addr] of conn_info  &create_expire=3 secs &expire_func=expire_summary ; 
} 

event zeek_init()
{
	print fmt ("============================================="); 
	print fmt ("since we are using expire function to write the"); 
	print fmt ("log file, wait 5 seconds before hitting ^c"); 
	print fmt ("Notice: we got exit_only_after_terminate=T on the top"); 
	print fmt (" now examine conn_summary.log "); 
	print fmt ("============================================="); 
	
} 

event zeek_init() &priority=-5 
{ 
	Log::create_stream(training::conn_summary_LOG, [$columns=conn_info]);
        local f = Log::get_filter(training::conn_summary_LOG, "default");
        f$path = "conn_summary" ;
        Log::add_filter(training::conn_summary_LOG,f);
} 


function expire_summary ( t: table[addr] of conn_info, idx: addr): interval 
{ 
	local info: conn_info ; 
	info$start_time = t[idx]$start_time; 
	info$end_time = t[idx]$end_time ; 
	info$host_count = |t[idx]$hosts|; 
	info$conn_count = t[idx]$conn_count ; 

	Log::write(training::conn_summary_LOG, info); 

	return 0 secs ; 
} 

event new_connection(c: connection)
{
	local orig=c$id$orig_h ; 
	local resp=c$id$resp_h ; 

	
	if (orig !in summary)
	{
		local rec: conn_info ; 
		local h: set[addr] ; 
		rec$hosts=h ; 
		
		summary[orig]=rec; 
		summary[orig]$start_time = c$start_time ; 
	} 

	summary[orig]$end_time=c$start_time; 
	add summary[orig]$hosts [resp] ; 

	summary[orig]$conn_count += 1 ; 

} 

event zeek_done()
{

	for (i in summary) 	
		print fmt ("%s", summary[i]);
} 
	
	

