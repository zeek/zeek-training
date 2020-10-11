
module Test; 

redef exit_only_after_terminate=T;

export {

        type Ban_Idx: record {
                ip_ban: addr;
        };

        type Ban_Val: record {
                ip_ban: addr;
                source: string &optional;
                desc: string &optional;
        } ;

        global tor_ip_ban_feed_file= fmt ("%s/CURRENT.24hrs_ZEEK", @DIR) &redef; 
        global ip_ban_feed: table[addr] of Ban_Val = table() &redef ;

} 

event line(description: Input::TableDescription, tpe: Input::Event, left: Ban_Idx, right: Ban_Val)
{
        if ( tpe == Input::EVENT_NEW ) {
		print fmt ("NEW"); 
        }


        if (tpe == Input::EVENT_CHANGED) {
        	print fmt ("CHANGED");
        }


        if (tpe == Input::EVENT_REMOVED ) {
               	print fmt ("REMOVED");
	} 	
} 

event zeek_init()
{

	 Input::add_table([$source=tor_ip_ban_feed_file, $name="tor_ip_ban_feed", $idx=Ban_Idx, $val=Ban_Val,  $destination=ip_ban_feed, $mode=Input::REREAD,$ev=line ]);
} 


event Input::end_of_data(name: string, source: string)
{
        print fmt ("end_of_data: name is %s source is %s", name, source);

	if (/CURRENT.24hrs_ZEEK/ in source) 
	{ 
		print fmt ("size of tables: ip_ban_feed: %s", |ip_ban_feed|);
	} 


}
