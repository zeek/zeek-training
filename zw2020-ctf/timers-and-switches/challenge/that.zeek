redef exit_only_after_terminate = T;

module Foo;
export {
  global table_touched: function(t: table[string] of count, tpe: TableChange, s: string, val: count);
  global my_table: table[string] of count &on_change=table_touched &write_expire=100msec;
  global entry_point: function();
  global new_e: event();
  global change_e: event();
  global remove_e: event();
  global alphabet: string = "abcdefghijklmnopqrstuvwxyz";
  global this: string = "";
}

function Foo::entry_point() {
  schedule 0msec { Foo::new_e() };
  schedule 0msec { Foo::new_e() };
  schedule 0msec { Foo::new_e() };
  schedule 100msec { Foo::new_e() };
  schedule 300msec { Foo::new_e() };
  schedule 500msec { Foo::new_e() };
}

event Foo::new_e() {
  for (i in Foo::alphabet) {
    if (i in Foo::my_table) {
      next;
    }
    Foo::my_table[i] = 2;    
    return;
  }
}

event Foo::change_e() {
  for (i in Foo::alphabet) {
    if (i in Foo::my_table) {
      Foo::my_table[i] += 1;
      return;
    }
  }
}

event Foo::remove_e() {
  for (i in Foo::alphabet) {
    if (i in Foo::my_table) {
      delete Foo::my_table[i];
      return;
    }
  }
}

function Foo::table_touched(t: table[string] of count, tpe: TableChange, s: string, val: count) {
  switch(tpe) {
    case TABLE_ELEMENT_NEW:
      Foo::this += "n";
      schedule 100msec { Foo::change_e() };
      break;
    case TABLE_ELEMENT_CHANGED:
      Foo::this += "c";
      schedule 170msec { Foo::remove_e() };
      break;
    case TABLE_ELEMENT_REMOVED:
      Foo::this += "r";
      schedule 70msec { Foo::new_e() };
      break;
    case TABLE_ELEMENT_EXPIRED:
      Foo::this += "e";
      schedule 300msec { Foo::new_e() };
      break;
    default:
      break;
    }
}

event zeek_init() {
  Foo::entry_point();
}
