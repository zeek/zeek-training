
module training;

# the following redef doesn't let zeek exit unitl
# you ^c out of it.

redef exit_only_after_terminate = T ;

export {

    global run_count: int=0 ;
    global my_event: event ();
}


event my_event()
    {
        run_count += 1;

        print fmt ("my_event ran: %s times", run_count);

        schedule 1 secs { training::my_event() };
    }


event zeek_init()
    {
        print fmt ("firing my_event");
        event training::my_event();
    }


event zeek_done()
    {
    print fmt ("=====================================================");
    print fmt ("try running the code after removing all instances of ");
    print fmt (" training::");
    print fmt ("");
    print fmt ("why do you think my_event() is not running anymore ?");
    print fmt ("=====================================================");
    }

