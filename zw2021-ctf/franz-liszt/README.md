Franz Liszt
===========

The pcap was recorded from your company's next-next-gen firewall-ng. It contains an SSH session from a threat actor who somehow gained access to one of your servers.
Recent threat intel reporting from CrowdAltoEye named the threat actor PIANO FINGERS because the actor is a master typist and never makes mistakes (and never uses the backspace or arrow keys while typing).


Here is some additional context we can provide you:
- The server was running Ubuntu 20.04.
- The attacker authenticated with their password.
- The attacker was then provided a pseudo-terminal on the server.
- Somehow the attacker had root privs on the box. To escalate priveledges, the attacker issued the "sudo su" command. The attacker then typed their password and successfully elevated to root.
- The attacker ran some commands before escalating to root. After doing so they ran some commands as root. We don't know what any of the commands typed or output were.


Your task is to see if you can determine the attacker's password length. This, as a digit, is the flag. For example, if the attacker's password is 8 characters long, the flag would be "8" (without quotes).
YOU ONLY GET 2 ATTEMPTS. DON’T WASTE THEM.
