@load base/frameworks/cluster

module DNS;

export {

	redef enum Notice::Type += {
		NetBIOS,
	};

	global netbios_queries: table[addr] of count &create_expire = 1 day;

	const netbios_threshold: vector of count = {
		1, 5, 10, 25, 100, 1000, 10000, 100000,
	} &redef;

	global netbios_threshold_idx: table[addr] of count
		&default=0 &write_expire = 1 day &redef;

}

event DNS::aggregate_stats(request_ip: addr, query: string, qtype_name: string, rcode_name: string)&priority=-10
{

	if (qtype_name != "NETBIOS")
		return;

	if (request_ip !in netbios_queries)
		netbios_queries[request_ip] = 0;

	netbios_queries[request_ip] += 1;

	local n = netbios_queries[request_ip];
	local check_thresh = check_threshold(netbios_threshold, netbios_threshold_idx, request_ip, n);

	if (check_thresh)
	{
		local msg = fmt("IP[%s] has done %s NetBIOS name queries (udp/137)", request_ip, n);
		NOTICE([$note=DNS::NetBIOS, $src=request_ip, $n=n, $msg=msg, $identifier=cat(request_ip), $suppress_for=1 min]);
	}

}

# NetBIOS name service (udp/137) is parsed by Zeek's DNS analyzer, which
# logs it in dns.log with opcode_name "netbios-query" and no qtype_name.
# We only care about external IPs probing our hosts.
event DNS::log_dns(rec: DNS::Info)
{
	local request_ip = rec$id$orig_h;

	# not interested in local_nets
	if (Site::is_local_addr(request_ip))
		return;

	if (rec$id$resp_p != 137/udp)
		return;

	local query = rec?$query ? rec$query : "-";
	local rcode_name = (!rec?$rcode_name) ? "UNKNOWN" : rec$rcode_name;

	@if ( Cluster::is_enabled())
		Cluster::publish_hrw(Cluster::proxy_pool, request_ip, DNS::aggregate_stats, request_ip, query, "NETBIOS", rcode_name);
	@else
		event DNS::aggregate_stats(request_ip, query, "NETBIOS", rcode_name);
	@endif

}
