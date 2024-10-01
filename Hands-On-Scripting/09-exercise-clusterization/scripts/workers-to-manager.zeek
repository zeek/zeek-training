event worker_to_manager(worker_name: string)
    {
    print fmt ("worker_to_manager %s got event from %s", peer_description, worker_name);
    }

event some_event_handled_on_worker()
    {
    Broker::publish(Cluster::manager_topic, worker_to_manager,
                    Cluster::node);
    }


event zeek_init()
{
	schedule 10 secs { some_event_handled_on_worker() } ; 

} 
