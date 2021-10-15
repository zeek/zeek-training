@load base/frameworks/notice

redef enum Notice::Type += {
    WhatTheZeek
};

event connection_established(c: connection)
    {
    local n = Notice::Info($note=WhatTheZeek, $conn=c, $msg=fmt("I saw a connection from %s", c$id$orig_h));
    NOTICE(n);
    }

#=================
# Filter out by notice type

#redef Notice::ignored_types += {
#    WhatTheZeek
#};

#=================
# Do a hook to filter things

option my_scanners: set[subnet] = {};

#redef Config::config_files += { "my-scanners.txt" };

hook Notice::policy(n: Notice::Info) &priority=20
    {
    #if ( n?$id && n$id$resp_h == 72.21.211.173 )
    if ( n?$id && n$id$resp_h in my_scanners )
        break;
    }
