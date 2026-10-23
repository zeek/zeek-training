all: zeek-intro-training.html

%.html: %.md
	marp-zeek.sh $< -o $@

# This needs monolith, from
# https://github.com/Y2Z/monolith
all-in-one: zeek-intro-training.html
	monolith file:///$$(pwd)/zeek-intro-training.html > zeek-intro-training-aio.html
