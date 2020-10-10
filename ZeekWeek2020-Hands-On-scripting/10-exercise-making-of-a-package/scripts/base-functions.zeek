module DNS ; 


export {

        global log_reporter:function(msg: string, debug: count);
        global check_threshold: function(v: vector of count, idx: table[addr] of count, orig: addr, n: count):bool;

	global DNS::aggregate_stats: event(request_ip: addr, query: string, qtype: string, rcode_name: string);
}

function check_threshold(v: vector of count, idx: table[addr] of count, orig: addr, n: count):bool
{

 #print fmt ("orig: %s and IDX_orig: %s and n is: %s and v[idx[orig]] is: %s", orig, idx[orig], n, v[idx[orig]]);
 if ( idx[orig] < |v| && n >= v[idx[orig]] )
                {
                ++idx[orig];

               return (T);
                }
        else
                return (F);
}

function log_reporter(msg: string, debug: count)
{

        #if (debug < 10)
        #       return ;

       @if ( ! Cluster::is_enabled())
        print fmt("%s", msg);
       @endif

        event reporter_info(network_time(), msg, peer_description);

}

