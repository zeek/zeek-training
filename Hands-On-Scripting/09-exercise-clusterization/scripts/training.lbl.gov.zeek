redef Log::print_to_log = Log::REDIRECT_STDOUT;

@load workers-to-proxy.zeek
@load manager-to-workers.zeek
@load workers-to-manager.zeek
@load workers-to-workers.zeek
