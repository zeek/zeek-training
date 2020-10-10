event worker_to_workers(worker_name: string)
    {
@if ( Cluster::local_node_type() == Cluster::MANAGER ||
      Cluster::local_node_type() == Cluster::PROXY )
        Broker::publish(Cluster::worker_topic, worker_to_workers,
                        worker_name);
@else
        print fmt ("worker_to_workers: %s got event from %s", peer_description, worker_name);
@endif
    }

event some_event_handled_on_worker()
    {
    # We know the manager is connected to all workers, so we could
    # choose to relay the event across it.
    Broker::publish(Cluster::manager_topic,  worker_to_workers,
                    Cluster::node + " (via manager)");

    # We also know that any given proxy is connected to all workers,
    # though now we have a choice of which proxy to use.  If we
    # want to distribute the work associated with relaying uniformly,
    # we can use a round-robin strategy.  The key used here is simply
    # used by the cluster framework internally to keep track of
    # which node is up next in the round-robin.
    local pt = Cluster::rr_topic(Cluster::proxy_pool, "example_key");
    Broker::publish(pt, worker_to_workers,
                    Cluster::node + " (via a proxy)");
    }

event zeek_init()
{
	schedule 10 secs { some_event_handled_on_worker() } ; 
} 
