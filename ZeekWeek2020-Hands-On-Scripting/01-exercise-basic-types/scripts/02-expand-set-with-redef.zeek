module training;

export { 
	global ip: set[addr] = {1.1.1.1, 1.1.1.2} &redef; 
} 


redef ip += {2.3.4.5} ; 

event zeek_done()
    {

	for (i in ip) 
		print fmt("ips in ip: %s", i); 



	print fmt ("======================================================="); 
	print fmt (""); 
	print fmt ("Note: since set 'ip' was &redef'ed "); 
	print fmt ("it can be expanded. Note += or else"); 
	print fmt ("previous values will be lost"); 
	print fmt (""); 
	print fmt ("Note 2: Since ip is exported, its meaningful"); 
	print fmt ("and less error-prone to reference it as training::ip"); 
	print fmt ("esp when clusterization is involved and possible that"); 
	print fmt ("variable is used inside other modules/namespaces"); 
	print fmt ("======================================================="); 
    } 


