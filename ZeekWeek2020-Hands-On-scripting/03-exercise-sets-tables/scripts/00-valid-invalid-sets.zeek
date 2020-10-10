
module test; 

export {
	global anew: set[addr] = {1.1.1.1, 1.1.1.2}; 
	global bnew: set[addr] = {3.3.3.3} ; 

	global aport = 22/unknown ; 


} 

event zeek_init()
{
	
	print fmt ("1. unknown port is %s", aport); 

	if (anew != bnew)
		print "1. anew != bnew" ; 

	print fmt ("2. union of sets: %s", anew|bnew); 
	print fmt ("3. intersection of sets: %s", anew&bnew); 
	print fmt ("4. difference of sets: %s", anew - bnew); 
	
	local a = www.google.com;

	print fmt ("5. a is %s", a); 
	
	local ai: interval = -1 min ; 
	
	print  fmt ("6: ai is %s", |ai|); 
} 
