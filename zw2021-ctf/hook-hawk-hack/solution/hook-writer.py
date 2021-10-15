import string
import random

pain_level = 100
used_letters = ["kh"]
vowels = ["a", "e", "i", "o", "u"]
hook_declarations = ""
hook_definitions = []

print("type huuk: record { hiik: string &default=\"\"; };")
for i in xrange(pain_level):
  letters = None
  while not letters:
    l1 = random.choice(string.ascii_lowercase)
    l2 = random.choice(string.ascii_lowercase)
    letters = l1+l2
    if letters in used_letters or l1 in vowels or l2 in vowels:
      letters = None
    else:
      used_letters.insert(0, letters)
  hook_declarations += "global h{}k: hook(heek: huuk);\n".format(letters)
hook_declarations += "global hkhk: hook(heek: huuk);\n"
print(hook_declarations)

for i in xrange(len(used_letters)-1):
  hook_def = ""
  hook_def += "hook h{}k(heek: huuk)".format(used_letters[i])
  hook_def += " {\n"
  hook_def += "  heek$hiik += \"{}\";\n".format(used_letters[i])
  hook_def += "  if (hook h{}k(heek))".format(used_letters[i+1])
  hook_def += " {\n"
  hook_def += "    ;\n"
  hook_def += "  } else {\n"
  hook_def += "    break;\n"
  hook_def += "  }\n"
  hook_def += "}\n"
  hook_definitions.append(hook_def)

last_hook_def = ""
last_hook_def += "hook hkhk(heek: huuk) {\n"
last_hook_def += "  heek$hiik += \"hk\";\n"
last_hook_def += "  if (T) {\n"
last_hook_def += "    ;\n"
last_hook_def += "  } else {\n"
last_hook_def += "    break;\n"
last_hook_def += "  }\n"
last_hook_def += "  print heek$hiik;\n"
last_hook_def += "}\n"
hook_definitions.append(last_hook_def)

random.shuffle(hook_definitions)
for h in hook_definitions:
  print(h)

print("print hook h{}k([$hiik=\"haak+\"]);".format(used_letters[0]))
