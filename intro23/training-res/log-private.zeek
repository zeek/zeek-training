redef record Conn::Info += {
    is_private: bool &default=F &log;
};

event connection_state_remove(c: connection)
   {
    if ( c$id$resp_h in Site::private_address_space )
        c$conn$is_private = T;
   }

