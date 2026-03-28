module DNS;

export {
	redef enum Notice::Type += { HostThreshold, QueryThreshold, };

	const host_threshold: vector of count = { 100, 250, 500, 1000, 5000, 10000,
	    100000, 200000, 300000, 400000, 500000, 800000, 1000000,  } &redef;

	global host_threshold_idx: table[addr] of count &default=0 &write_expire=1day;

	global DNS::summary: event(src: addr, resp: addr, query: string,
	    qtype_name: string, rcode_name: string);

	type dns_summary: record {
		num_query: count &default=0;
		query: opaque of cardinality &default=hll_cardinality_init(0.1, 0.999);
		hosts: opaque of cardinality &default=hll_cardinality_init(0.1, 0.999);
		qtype_name: table[string] of count &write_expire=1day;
		first_seen: time;
		last_seen: time;
	};

	global expire_heavy_hitters: function(t: table[addr] of dns_summary, v: addr)
	    : interval;
	global heavy_hitters: table[addr] of dns_summary &create_expire=1day
	    &expire_func=expire_heavy_hitters;

	global print_heavy_hitters: function(src: addr): string;
	global get_val_size: event();
}

function expire_heavy_hitters(t: table[addr] of dns_summary, v: addr): interval
	{
	#print fmt ("Expire: %s, %s", v, t[v]);
	return 0secs;
	}

event DNS::log_dns(rec: DNS::Info) &priority=-15
	{
	local src = rec$id$orig_h;
	local resp = rec$id$resp_h;

	if ( Site::is_local_addr(src) )
		return;

	if ( ! rec?$rcode_name )
		local rcode_name = "UNKNOWN";
	else
		rcode_name = rec$rcode_name;

	local qtype_name = rec?$qtype_name ? rec$qtype_name : "Unknown";
	local query = rec?$query ? rec$query : "Unknown";

@if ( Cluster::is_enabled() )
	Cluster::publish_hrw(Cluster::proxy_pool, src, DNS::summary, src, resp, query,
	    qtype_name, rcode_name);
@else
	event DNS::summary(src, resp, query, qtype_name, rcode_name);
@endif
	}

event DNS::summary(src: addr, resp: addr, query: string, qtype_name: string,
    rcode_name: string) &priority=-10
	{
	if ( src !in heavy_hitters )
		{
		local ap: dns_summary;
		heavy_hitters[src] = ap;
		heavy_hitters[src]$qtype_name = table();
		heavy_hitters[src]$first_seen = network_time();
		}

	heavy_hitters[src]$num_query += 1;
	hll_cardinality_add(heavy_hitters[src]$query, query);
	hll_cardinality_add(heavy_hitters[src]$hosts, resp);

	if ( qtype_name !in heavy_hitters[src]$qtype_name )
		{
		heavy_hitters[src]$qtype_name[qtype_name] = 0;
		}

	heavy_hitters[src]$qtype_name[qtype_name] += 1;
	heavy_hitters[src]$last_seen = network_time();

	local n = double_to_count(hll_cardinality_estimate(heavy_hitters[src]$hosts));
	local check_thresh = check_threshold(host_threshold, host_threshold_idx, src, n);
	local msg = "";

	if ( check_thresh )
		{
		msg = fmt("%s", print_heavy_hitters(src));
		NOTICE([ $note=DNS::HostThreshold, $src=src, $msg=msg, $identifier=cat(src),
		    $suppress_for=1min ]);
		}

	n = double_to_count(hll_cardinality_estimate(heavy_hitters[src]$query));
	check_thresh = check_threshold(query_threshold, query_threshold_idx, src, n);

	if ( check_thresh )
		{
		msg = print_heavy_hitters(src);
		NOTICE([ $note=DNS::QueryThreshold, $src=src, $msg=msg, $identifier=cat(src),
		    $suppress_for=1min ]);
		}
	}

# [ts=1596366431.199041, uid=CY9yrx4jcEeEo2RTnk, id=[orig_h=137.74.213.136, orig_p=13938/udp, resp_h=131.243.64.3, resp_p=53/udp], proto=udp, trans_id=56404, rtt=<uninitialized>, query=181.139.146.in-addr.arpa, qclass=1, qclass_name=C_INTERNET, qtype=1, qtype_name=A, rcode=3, rcode_name=NXDOMAIN, AA=F, TC=F, RD=F, RA=F, Z=1, answers=<uninitialized>, TTLs=<uninitialized>, rejected=F, total_answers=0, total_replies=2, saw_query=T, saw_reply=T]

function print_heavy_hitters(src: addr): string
	{
	local qcount = double_to_count(hll_cardinality_estimate(
	    heavy_hitters[src]$query));
	local rcount = double_to_count(hll_cardinality_estimate(
	    heavy_hitters[src]$hosts));
	local qtype = "";

	for ( a in heavy_hitters[src]$qtype_name )
		qtype += fmt(" [%s]: %s", a, heavy_hitters[src]$qtype_name[a]);

	local msg = fmt(
	    "IP[%s], numQueries: %s, uniqQueries: %s, Hosts: %s, Qtype: %s",
	    src, heavy_hitters[src]$num_query, qcount, rcount, qtype);

	return msg;
	}
