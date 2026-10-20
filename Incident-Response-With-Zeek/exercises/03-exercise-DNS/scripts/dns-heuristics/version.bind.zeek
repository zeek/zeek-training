@load base/frameworks/cluster

module DNS;

export {

	redef enum Notice::Type += {
		VersionBind,
	};

	global version_bind_queries: table[addr] of count &create_expire = 1 day;

	const version_bind_threshold: vector of count = {
		1, 10, 100, 250, 500, 1000, 10000, 50000, 100000, 1000000,
	} &redef;

	global version_bind_threshold_idx: table[addr] of count
		&default=0 &write_expire = 1 day &redef;

	# CHAOS-class TXT query that reveals the DNS server software/version
	global version_bind_queries_pattern: pattern = /version\.bind/ &redef;

}

event DNS::aggregate_stats(request_ip: addr, query: string, qtype_name: string, rcode_name: string)&priority=-10
{

	if (qtype_name != "VERSION_BIND")
		return;

	if (request_ip !in version_bind_queries)
		version_bind_queries[request_ip] = 0;

	version_bind_queries[request_ip] += 1;

	local n = version_bind_queries[request_ip];
	local check_thresh = check_threshold(version_bind_threshold, version_bind_threshold_idx, request_ip, n);

	if (check_thresh)
	{
		local msg = fmt("IP[%s] has done %s version.bind look ups", request_ip, n);
		NOTICE([$note=DNS::VersionBind, $src=request_ip, $n=n, $msg=msg, $identifier=cat(request_ip), $suppress_for=1 min]);
	}

}

# we only care about external IPs asking our dns_servers for their version
event DNS::log_dns(rec: DNS::Info)
{
	local request_ip = rec$id$orig_h;

	# not interested in local_nets
	if (Site::is_local_addr(request_ip))
		return;

	# only interested in TXT queries for version.bind
	if (!rec?$qtype_name || rec$qtype_name != "TXT" || !rec?$query)
		return;

	if (version_bind_queries_pattern !in to_lower(rec$query))
		return;

	local rcode_name = (!rec?$rcode_name) ? "UNKNOWN" : rec$rcode_name;

	@if ( Cluster::is_enabled())
		Cluster::publish_hrw(Cluster::proxy_pool, request_ip, DNS::aggregate_stats, request_ip, rec$query, "VERSION_BIND", rcode_name);
	@else
		event DNS::aggregate_stats(request_ip, rec$query, "VERSION_BIND", rcode_name);
	@endif

}
