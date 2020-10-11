module training; 


export {

	type conn_info: record {
		start_time : time ; 
		end_time: time ; 
		conn_count: count &default=0 ; 
		hosts: set[addr];
	} ; 


	global stats: table[addr] of conn_info ; 
} 


event zeek_init()
{
	print fmt ("======================================="); 
	print fmt ("In this dump below you can see contents"); 
	print fmt ("of stats table which  contains conn_info record"); 
	print fmt (""); 
	print fmt("type conn_info: record {"); 
	print fmt("     start_time : time ; "); 
	print fmt("     end_time: time ; "); 
        print fmt("     conn_count: count &default=0 ; "); 
 	print fmt("     hosts: set[addr];"); 
	print fmt ("}"); 
	print fmt ("======================================="); 
	print fmt ("try printing individual memebrs of the record"); 
	print fmt ("Hint: you can use $ operator"); 
	print fmt ("======================================="); 
} 

event new_connection(c: connection)
{
	local orig=c$id$orig_h ; 
	local resp=c$id$resp_h ; 

	
	if (orig !in stats)
	{
		local rec: conn_info ; 
		local h: set[addr] ; 
		rec$hosts=h ; 
		
		stats[orig]=rec; 
		stats[orig]$start_time = c$start_time ; 
	} 

	stats[orig]$end_time=c$start_time; 
	add stats[orig]$hosts [resp] ; 

	stats[orig]$conn_count += 1 ; 

} 

event zeek_done()
{

	for (i in stats) 	
		print fmt ("%s -> %s", i,stats[i]); 
} 
	
	

