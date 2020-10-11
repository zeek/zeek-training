event manager_to_workers(s: string)
    {
    print fmt ("manager_to_workers: %s got event %s", peer_description, s);
    }

event some_event_on_manager()
    {

    local msg = fmt ("%s", peer_description) ; 

    Broker::publish(Cluster::worker_topic, manager_to_workers,
                   fmt("hello v0: from %s", msg));

    # If you know this event is only handled on the manager, you don't
    # need any of the following conditions, they're just here as an
    # example of how you can further discriminate based on node identity.

    # Can check based on the name of the node.
    if ( Cluster::node == "manager" )
        Broker::publish(Cluster::worker_topic, manager_to_workers,
                        fmt("hello v1: from %s",msg));

    # Can check based on the type of the node.
    if ( Cluster::local_node_type() == Cluster::MANAGER )
        Broker::publish(Cluster::worker_topic, manager_to_workers,
                        fmt ("hello v2: from %s",msg));

    # The run-time overhead of the above conditions can even be
    # eliminated by using the following conditional directives.
    # It's evaluated once per node at parse-time and, if false,
    # any code within is just ignored / treated as not existing at all.
@if ( Cluster::local_node_type() == Cluster::MANAGER )
        Broker::publish(Cluster::worker_topic, manager_to_workers,
                        fmt("hello v3: from %s",msg));
@endif
    }


event zeek_init()
{
	schedule 10 secs { some_event_on_manager() } ; 
} 
