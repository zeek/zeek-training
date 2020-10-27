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


event zeek_init() {

	print fmt ("%s", blacklist_file); 

    Input::add_table([$source=blacklist_file, $name="blacklist", $idx=Idx, $val=Val, $destination=blacklist]);
    Input::remove("blacklist");
}


event Input::end_of_data(name: string, source: string) 
    {

        print fmt ("firing end_of_data event "); 
        print fmt ("now all data is in the table"); 
        print fmt (""); 
        print fmt (""); 
        print fmt (""); 

        print fmt ("Number of records read: %s", |blacklist|); 

        print blacklist;
    }
