event worker_to_proxies(worker_name: string)
    {
    print fmt ("worker_to_proxies: %s got event from %s", peer_description, worker_name);
    }

global my_counter = 0;

event some_event_handled_on_worker()
    {
    # The key here is used to choose which proxy shall receive
    # the event.  Different keys may map to different nodes, but
    # any given key always maps to the same node provided the
    # pool of nodes remains consistent.  If a proxy goes offline,
    # that key maps to a different node until the original comes
    # back up.
    Cluster::publish_hrw(Cluster::proxy_pool,
                         cat("example_key", ++my_counter),
                         worker_to_proxies, Cluster::node);
    }
