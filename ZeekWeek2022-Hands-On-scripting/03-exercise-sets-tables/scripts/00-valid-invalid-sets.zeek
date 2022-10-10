module test; 

export {
	global anew: set[addr] = {1.1.1.1, 1.1.1.2, 1.1.1.3, 1.1.1.4, 3.3.3.3}; 
	global bnew: set[addr] = {3.3.3.3} ; 
	global cnew: set[addr] = {3.3.3.3} ; 
} 

event zeek_init()
{
	
	print fmt ("The following shows some set operations"); 
	print fmt ("") ; 
	print fmt ("") ; 
	print fmt ("======================================================") ; 

	if (anew != bnew)
		print "1. anew != bnew" ; 

	print fmt ("2. union of sets: %s", anew|bnew); 
	print fmt ("3. intersection of sets: %s", anew&bnew); 
	print fmt ("4. difference of sets: %s", anew - bnew); 
	
	local a = www.google.com;

	print fmt ("5. a is %s", a); 

	if (1.1.1.1 in anew)
		print fmt ("6. 1.1.1.1 is in %s", anew); 
	
	if (2.1.1.1 !in anew)
		print fmt ("7. 2.1.1.1 is !in %s", anew); 

	local _list  = fmt ("8. Members of a new: ");
	for (ips in anew)
		_list += fmt ("%s ", ips); 

	print fmt ("%s", _list); 

    if (bnew == cnew) 
        print fmt ("9: both sets are equal"); 

    if (anew >  cnew)
        print fmt ("10: cnew is a subset of anew: %s", anew > cnew) ; 

	print fmt ("======================================================") ; 


	
} 
