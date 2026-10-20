# how many times do you do that in a given duration (say 5 mins ) ?

# total number of lookups per IP per day
# acceleration/spike: fastest/quickest threshold reacher

# 1. count all the lookups per IP for 1 min
# 2.  check if the threshold for above IP is reached - cache the threshold counter for 1 mins
# 3. if threshold is hit, increment rate counter by 1
# 4. expire counters and data from tables after 1 min
# 5. check if rate_counter > rolling_threshold
#	if yes - fire alert
# 6. Repeat 1, 2, 3, 4
# 7. check if rate_counter has expired, set to zero
# loop

@load base/frameworks/cluster
@load base/frameworks/notice
@load base/protocols/dns

module DNS;


export {

        redef enum Notice::Type += {
                Threshold,
                Spike,
        };

	# Worker -> HRW-selected proxy aggregation event for spike/daily
	# threshold detection. All copies of one source IP's queries are routed
	# (by HRW on request_ip) to the SAME proxy, which owns the state tables
	# below and performs the time-window math + NOTICEs. This re-concentrates
	# a single source IP's queries onto one node even though Zeek's packet
	# load-balancing spreads them across workers by 5-tuple. `ts` carries the
	# original packet timestamp (rec$ts) so the 1-second spike window is
	# measured in packet time, not proxy arrival time. Mirrors the HRW
	# pattern used by dns-hitters/txt/ptr/zonetransfer in this package.
	global dns_spike_threshold: event(request_ip: addr, ts: time);

        const dns_threshold: vector of count = {
                100000, 200000, 300000, 400000, 500000, 800000, 1000000,
        } &redef;

	const dns_spike_counters: vector of count = {
	   	 100,
        } &redef;

	const Spike_Threshold = 400  &redef;
	const Spike_Rolling_Threshold = 3 &redef ;

type DNS_SpikeThresholdRecord: record {
	 first_seen_time: time &optional;
	 cur_time: time &optional;
	 tally: count &log &default=0;
	} ;




global flush_dns_spike_ip_counter:function (t: table[addr] of DNS_SpikeThresholdRecord, orig: addr): interval;

	global dns_spike_ip_counter: table[addr] of DNS_SpikeThresholdRecord
                        &create_expire= 1 sec &expire_func=flush_dns_spike_ip_counter  &redef;

	# (dns_spike_idx, a 100msec table, was declared but only referenced in a
	# commented-out debug schedule -- dead code, removed during clusterization.)

	global dns_spike_idx_2: table[addr] of count
                        &default=0 &create_expire= 3 min &redef;

	global dns_servers: set[addr] &redef;
	#global dns_servers: set[addr] += { 128.3.34.186, 131.243.64.2, 131.243.64.3, [2620:83:8000:140::3], 131.243.5.1} &redef ;

	redef DNS::dns_servers += { 131.243.121.19, 131.243.5.2, 128.3.34.186, 131.243.64.2, 131.243.64.3, [2620:83:8000:140::3], [2620:83:8000:140::2], 131.243.5.1, 131.243.84.10} ;

	global ok_threshold: set[addr] &redef ;

	# we don't want to ignore the counts, but only ignore the emails
	#redef DNS::dns_servers += ignore_thresholds ;

	global dns_ip_thresholds: table[addr] of count
                        &create_expire= 1 days &redef;

	global dns_ip_threshold_idx: table[addr] of count
                        &default=0 &write_expire = 1 day &redef;

	const ok_dns_spike_host: set[addr] &redef ;

}

#hook Notice::policy (n: Notice::Info) {
#   if ( n$note == DNS::Threshold && n$src !in DNS::ok_threshold)
#		{ add n$actions[Notice::ACTION_EMAIL];}
#   if (n$note == DNS::Spike && n$src !in DNS::ok_dns_spike_host)
#		{ add n$actions[Notice::ACTION_EMAIL];}
#  }

event zeek_init() &priority=5
{
# 	schedule 2 sec {print_tables(dns_spike_ip_counter, dns_spike_idx, dns_spike_idx_2)};
}


function flush_dns_spike_ip_counter(t: table[addr] of DNS_SpikeThresholdRecord, orig: addr): interval
{
	delete t[orig]  ;
	return 0sec;
}

function check_ip_threshold(v: vector of count, idx: table[addr] of count, orig: addr, n: count):bool
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




# Worker side: filter to relevant queries, then route to the HRW-selected
# proxy keyed on request_ip so all of one source IP's queries are counted on a
# single node. In standalone/pcap mode this fires the handler locally and
# behaves exactly as the old inline code did.
event DNS::log_dns(rec: DNS::Info)
{
	local request_ip = rec$id$orig_h  ;

	if (rec?$query && request_ip !in dns_servers) {

		@if ( Cluster::is_enabled() )
			Cluster::publish_hrw(Cluster::proxy_pool, request_ip,
			                     DNS::dns_spike_threshold, request_ip, rec$ts);
		@else
			event DNS::dns_spike_threshold(request_ip, rec$ts);
		@endif
	}
} # end of event

# Authoritative spike + daily-threshold detection. In cluster mode this runs on
# the HRW-selected proxy (which owns all the state tables); on workers it must
# return early so per-worker state never diverges. In standalone mode it runs
# in-process. `ts` is the original packet timestamp (rec$ts) so the 1-second
# spike window is measured in packet time, not proxy arrival time.
event DNS::dns_spike_threshold(request_ip: addr, ts: time)
{
	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::PROXY )
		return;

	local check_thresh: bool;
	local msg ="";

	{
		local thresh_rec: DNS_SpikeThresholdRecord;


		if(request_ip !in dns_spike_ip_counter) {
			thresh_rec$tally= 1;
			thresh_rec$first_seen_time = ts;
			thresh_rec$cur_time= ts;
			dns_spike_ip_counter[request_ip] = thresh_rec;

		}
			thresh_rec$tally = dns_spike_ip_counter[request_ip]$tally + 1 ;
			thresh_rec$cur_time= ts;
			thresh_rec$first_seen_time  = dns_spike_ip_counter[request_ip]$first_seen_time;
			dns_spike_ip_counter[request_ip] = thresh_rec;

			local n = |dns_spike_ip_counter[request_ip]$tally| ;


		#i   print fmt ("IP [%s]: tally: %d", request_ip, n);



		if ((dns_spike_ip_counter[request_ip]$cur_time - dns_spike_ip_counter[request_ip]$first_seen_time) <= 1 sec)
		{

			n = |dns_spike_ip_counter[request_ip]$tally| ;

				if (n >= Spike_Threshold)
				{

#				print fmt ("IP: [%s] ==>  %s", request_ip, dns_spike_ip_counter[request_ip]);

					msg = fmt("IP[%s] has done %s (First:%s, cur: %s, diff: %s) look ups: %d", request_ip, dns_spike_ip_counter[request_ip]$tally, dns_spike_ip_counter[request_ip]$first_seen_time, dns_spike_ip_counter[request_ip]$cur_time, dns_spike_ip_counter[request_ip]$cur_time - dns_spike_ip_counter[request_ip]$first_seen_time, n);
					#local msg = fmt ("ip_counter[%s]:  %s", request_ip, dns_spike_ip_counter[request_ip]$tally);
					local time_diff:interval;

					if (request_ip !in dns_spike_idx_2)
						dns_spike_idx_2[request_ip]=0 ;

					dns_spike_idx_2[request_ip]+=1 ;

					time_diff = dns_spike_ip_counter[request_ip]$cur_time - dns_spike_ip_counter[request_ip]$first_seen_time ;
					delete dns_spike_ip_counter[request_ip] ;

					#print fmt ("INSIDE: dns_spike_idx_2[%s] %s is %d",request_ip, dns_spike_idx_2[request_ip],|dns_spike_idx_2[request_ip]|);

					if (|dns_spike_idx_2[request_ip]| >= DNS::Spike_Rolling_Threshold)
					{
						 if (time_diff < 60 sec ) {
							# $suppress_for is set EXPLICITLY to 1hr to preserve the
							# notice's historical effective dedup window (it previously
							# had no $suppress_for and inherited Zeek's 1hr default).
							# Making it explicit also makes cluster-wide dedup behavior
							# unambiguous now that the NOTICE fires from the proxy.
							NOTICE([$note=DNS::Spike, $src=request_ip, $msg=msg, $identifier=cat(request_ip), $suppress_for=1 hr]);
							#print fmt ("Consistant threshold reached for %s : %s in %s", request_ip, |dns_spike_idx_2[request_ip]|, time_diff );


						}


					}

				}  # n > spike_threshold
		} # <= 1 sec
		else
			{
#				print fmt (" DIFF: request_ip[%s] - %s, count: %d", request_ip, dns_spike_ip_counter[request_ip]$cur_time - dns_spike_ip_counter[request_ip]$first_seen_time, dns_spike_ip_counter[request_ip]$tally );
				delete dns_spike_ip_counter[request_ip] ;
				delete dns_spike_idx_2[request_ip];

			}

	# look for thresholds over the day duration

                if(request_ip !in dns_ip_thresholds)
                        dns_ip_thresholds[request_ip] = 1 ;

                dns_ip_thresholds[request_ip] += 1;

                n = |dns_ip_thresholds[request_ip]| ;

                check_thresh =  check_ip_threshold(dns_threshold, dns_ip_threshold_idx, request_ip, n);

                if (check_thresh) {
			#print fmt ("IP [%s] has done %d lookups: %d", request_ip, dns_ip_thresholds[request_ip],n);
			msg = fmt ("IP[%s] has done %s look ups: %d", request_ip, dns_ip_thresholds[request_ip], n);
			NOTICE([$note=DNS::Threshold, $src=request_ip, $msg=msg, $identifier=cat(request_ip), $suppress_for=1 min]);
                }


	}# if dns

} # end of event




# Query is [ts=1354067276.222667, uid=lJ3m7xcr1X6, id=[orig_h=198.128.207.13, orig_p=58293/udp, resp_h=131.243.5.1, resp_p=53/udp], proto=udp, trans_id=22857, query=www-gm-opensocial.googleusercontent.com, qclass=1, qclass_name=C_INTERNET, qtype=1, qtype_name=A, rcode=0, rcode_name=NOERROR, AA=F, TC=F, RD=T, RA=T, Z=0, answers=[googlehosted.l.googleusercontent.com, 74.125.224.139, 74.125.224.140, 74.125.224.138], TTLs=[2.0 mins 52.0 secs, 2.0 mins 51.0 secs, 2.0 mins 51.0 secs, 2.0 mins 51.0 secs], ready=T, total_answers=4, total_replies=12]:
