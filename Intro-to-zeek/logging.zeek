# This creates a new log file, conn_S0, and logs
# all S0 (single SYN packet) connections to that log
# instead of conn.log

module LogFilter;

@ifdef ( Conn::Info )

export {
        redef enum Log::ID += { ConnS0_LOG };
}

hook pred_hook(stream: Log::ID, filter_name: string, rec: Conn::Info)
{
        if ( stream != Conn::LOG || filter_name != "default" )
                return;

        if ( rec?$conn_state && rec$conn_state == "S0" )
            {
                Log::write(ConnS0_LOG, rec);
                break;
                }
}

event LogFilter::initialized()
        {
        Log::create_stream(ConnS0_LOG, [$columns=Conn::Info, $path="conn_s0"]);
        }
@endif
