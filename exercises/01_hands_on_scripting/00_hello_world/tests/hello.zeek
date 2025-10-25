# This is the first exercise. Fix the line marked `TODO` below.

# This file contains a single test for Zeek's BTest testing framework,
# https://github.com/zeek/btest. You do not need to understand all its details,
# but what is happening here is that the lines marked `@TEST-EXEC` are executed
# in a shell and expected the pass.

##########################################
# Check whether you environment is set up correctly.

# Run `zeek --version` to make sure we can run `zeek`.
# @TEST-EXEC: zeek --version

# Run `btest --version` to make sure we can run `btest`. Since this is already
# only run with `btest` this probably should never not pass.
# @TEST-EXEC: btest --version

##########################################
# Run the actual tests.

# This line runs `zeek` with the current file as input. Stdout is saved to the file `output`.
# @TEST-EXEC: zeek %INPUT >output

# This line runs `btest-diff` to compare the file `output` against a snapshot.
# @TEST-EXEC: btest-diff output

##########################################
# This runs when zeek is starting up.
event zeek_init()
	{
	print "Hello world!";
	}

# This runs when zeek is shutting down.
event zeek_done()
	{
	# TODO: Make this print the string 'Goodbye world!'
	}
