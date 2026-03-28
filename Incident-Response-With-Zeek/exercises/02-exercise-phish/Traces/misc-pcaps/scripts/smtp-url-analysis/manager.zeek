module SMTPurl;

@load ./smtp-thresholds
#@load ./smtp-addressbook

export {
	global SMTPurl::new_smtp_rec: event(rec: SMTP::Info);
}

@if ( Cluster::is_enabled() )

@if ( Cluster::local_node_type() != Cluster::MANAGER )
event zeek_init()
	{
	Broker::auto_publish(Cluster::manager_topic, SMTPurl::new_smtp_rec);
	}
@endif
@endif

#@if ( Cluster::is_enabled() )
#@load base/frameworks/cluster
#redef Cluster::worker2manager_events += /SMTPurl::new_smtp_rec/;
#@endif

### (1) main event to tap into smtp records
event SMTP::log_smtp(rec: SMTP::Info) &priority=-5
	{
	#send log to manager
	if ( ! connection_exists(rec$id) )
		return;

	if ( ! rec?$from )
		return;

	### if standalone then we check on bro node else we deligate manager to handle this
@if ( Cluster::is_enabled() )
	event SMTPurl::new_smtp_rec(rec);
@else
	check_smtp_thresholds(rec);
	#process_addressbook(rec);
@endif
	}

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || ! Cluster::is_enabled() )
event SMTPurl::new_smtp_rec(rec: SMTP::Info) &priority=-10
	{
	check_smtp_thresholds(rec);
	#process_addressbook(rec);
	}
@endif
