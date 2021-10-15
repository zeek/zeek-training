@load policy/protocols/dns/auth-addl

module PutItInTheDNS;

event dns_EDNS_ecs(c: connection, msg: dns_msg, opt: dns_edns_ecs)
    {
    print fmt("%s/%s", opt$address, opt$source_prefix_len);
    }
