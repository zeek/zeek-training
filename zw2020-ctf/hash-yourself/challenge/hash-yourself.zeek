


redef exit_only_after_terminate = T;

module Baz; export {global f: function();}
module Foo;


global do_it = Exec::run;
module Bar;


module Foo::Bar;
export {

  module Bar;
  export {
    global Bar: string = "Foo";

    global Foo: string = "";
    global s: string = "Bar";
  }

  module Foo::Bar;
  export {
    global Bar: string = "";
    global s: string = "Foo";
    global Foo: string = "Bar";
  }

  module Foo;
  global s: string = "";
  global Bar: string = "Bar";
  global Foo: string = "Foo";

}

function Baz::f() {
  local magic = "rFj3eGxkRR5";
  when (local result = do_it([$cmd=fmt("cat %s", @FILENAME), $uid=magic])) {
    levenshtein_distance(md5_hash(join_string_vec(result$stdout, "\n")), s) - 3;
    terminate();
  }
}

event zeek_init() &priority=10 {
local c: count = 10;
Foo += "::s";
while (-100 > -101) {
  s += string_cat(fmt("%s",double_to_count(floor(haversine_distance(1.0, 1.0, 2.0, c)))));
  c -= 1;
  if (Foo in global_ids()) {
    s = lookup_ID(Foo);
  }
  if (c <= 0) break;
}
Baz::f();
}
