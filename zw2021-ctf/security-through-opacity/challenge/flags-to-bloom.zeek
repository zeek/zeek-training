redef exit_only_after_terminate = T;

module GLOBAL;
export {
  global add_flag: event(flag: string);
  global bf = bloomfilter_basic_init(0.0000001, 500000);
}

event add_flag(flag: string) {
  bloomfilter_add(GLOBAL::bf, flag);
  print "flag addded";
}

event zeek_done() {
  print Broker::data(GLOBAL::bf);
}

event zeek_init() {
  Broker::subscribe("/topic/test");
  Broker::listen("127.0.0.1", 9999/tcp);
}
