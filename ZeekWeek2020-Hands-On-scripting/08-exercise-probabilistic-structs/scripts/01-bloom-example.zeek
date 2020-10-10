export {
        global bf_ua: opaque of bloomfilter;
}

event zeek_init()
{ 
	bf_ua = bloomfilter_basic_init(0.0001, 1000000); 
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if ( name == "USER-AGENT") {
		
		local bf_result = bloomfilter_lookup(bf_ua,value);
		
		if (bf_result == 0 ) {
		      print value;
		      bloomfilter_add(bf_ua,value);
		    }
		else {    
			print "Value in bloomfilter";    
		}
	}
}

