
module test; 

export {
	global anew: set[addr] = {1.1.1.1, 1.1.1.2}; 
	global bnew: set[addr] = {3.3.3.3} ; 
} 

event zeek_init()
    {
	if (anew != bnew)
		print "1. anew != bnew" ; 

	print fmt ("2. union of sets: %s", anew|bnew); 
	print fmt ("3. intersection of sets: %s", anew&bnew); 
	print fmt ("4. difference of sets: %s", anew - bnew); 
    } 
