# This is the original, non-obfuscate, version of the script.

module SimpsonsEpisodeMaker;

export {
  global roles: table[string] of string = {
    ["Main"] = "The majority of the episode is based on what this character does",
    ["Comic Releif"] = "The major of bad fortune happens to this character through the episode",
    ["Build Up"] = "The first 1/3 of the episode is about this character and sets the stage for the last 2/3",
  };

  global participants: vector of string = {
    "Homer",  # D'oh!
    "Marge",
    "Lisa",
    "Bart",
    "Maggie",
    "Grandpa",
    "Santa's Little Helper",
    "Ned",
    "Hans Moleman",
    "Dr. Hibbert",
    "Moe",
    "Krusty"
  };

  # This is used as an exclusion filter in assign_roles. 
  global exclude: set[count] = {0};
  global assign_roles: function();
}

function SimpsonsEpisodeMaker::assign_roles() {
  for (role in SimpsonsEpisodeMaker::roles) {
    local i: count = 0;

    # Because exclude already contains the value 0, the first participant will always be skipped.
    # Poor Homer :(
    while (i in SimpsonsEpisodeMaker::exclude) {
      i = rand(|SimpsonsEpisodeMaker::participants|);
    }
    add SimpsonsEpisodeMaker::exclude[i];

    local p = SimpsonsEpisodeMaker::participants[i];
    local r = role;
    local d = SimpsonsEpisodeMaker::roles[role];
    print fmt("%s    %s    %s", p, r, d);
  }
}

event zeek_init() &priority=5 {
  SimpsonsEpisodeMaker::assign_roles();
}
