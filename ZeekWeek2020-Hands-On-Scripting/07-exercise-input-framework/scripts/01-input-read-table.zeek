module training; 

redef exit_only_after_terminate = T ; 


export { 
	type Idx: record {
		ip: addr;
	};

	type Val: record {
		timestamp: time;
		reason: string;
	};

	global blacklist: table[addr] of Val = table();
	global blacklist_file = fmt ("%s/blacklist.file", @DIR) ; 
    } 


event zeek_init() 
    {
    print fmt (""); 
    print fmt (""); 
    print fmt (""); 
    print fmt (""); 
	print fmt ("Blacklist file to use: %s", blacklist_file); 

    Input::add_table([$source=blacklist_file, $name="blacklist", $idx=Idx, $val=Val, $destination=blacklist]);
    Input::remove("blacklist");

    print fmt (""); 
    print fmt (""); 
    print fmt ("We are using 'exit_only_after_terminate = T;' "); 
    print fmt ("to give zeek time to read the input file");
    print fmt ("Press ^C to exit out of zeek and you'd see"); 
    print fmt ("out of the table blacklist"); 
    print fmt (""); 
    print fmt (""); 
    print fmt (""); 
    }


event zeek_done()
    {
    print fmt (""); 
    print fmt (""); 
    print fmt (""); 

    print fmt ("Dumping the contents of blacklist table"); 
	for (i in blacklist) 
		print fmt ("idx: %s value: %s", i,blacklist[i]); 
    } 

