doorman
=======

A password manager written in haskell by Joe Jevnik.

Last updated: 19.10.2013

Purpose:
--------

The purpose of `doorman` is to allow users to generate and employ very strong
passwords for various applications and websites without requiring them to need
to remember them, or save them in plain text anywhere. `doorman` allows users to
to safely store only 'seeds' of passwords that must be combined with a master
password in order to be retrieved. The master password is only ever stored
post-hash for comparison. Also, the files are all owned by a new user, also
named 'doorman', and only have read and write permisions for that user. the
application runs under doorman's permissions, so the only access to those files
can come through the `doorman` application, or 'root'. `doorman` can be invoked
from any terminal, but the intended use is to be invoked from dmenu or something
simmilar, where a user wouldn't have to leave the password prompt screen to
retrieve the password. This is also why the behavior is to push it directly to
the clipboard, as dmenu has no stdout.

Compiling:
----------

Required packages:

- `sha` - The package needed for hashing installed through `cabal install`.

- `xclip` - The x clipboard, installed through your distro's package manager
(pacman,yum,apt-get...).

I compiled with: `$ ghc --make -O2 doorman.hs`

Initializing:
-------------

Run the included shell script `setup` as root in the same directory as
the newly compiled `doorman` to do the follwing:

- Create the new user named 'doorman' without a home directory and who's shell
points to '/usr/bin/false'.

- Create the directory /usr/share/doorman and set its owner to 'doorman'.

- Create the two files `pass_lib` and `master` in that directory also with their
owners set to 'doorman'.

- Sets the owner of `doorman` to 'doorman' and copies it to '/usr/bin/doorman'.

- Sets `doorman` to run as its owner: 'doorman'.

- Calls `doorman -i` to set the first master password.


The reason for the new user 'doorman' is so that any user can call doorman,
provided they know the master password, howver non-root users cannot read or
write to the 'master' and 'pass_lib' files. This prevents users from affecting
the master hash and disallowing users from accessing their saved passwords, or
reading the seeds and attempting to generate a passoword from them (even though
you would still need the master pass to do so). Basically, this restricts access
to your master hash and password seeds to just the doorman program, where they
will always be handled safely.

NOTE: You can change the password at anytime with _however_ seeds will yeild new
results:

    $ doorman -m [NEWPASSWORD] [REPEATNEWMASTER] [OLDPASSWORD]


Usage:
------

`Usage: [OPTION] [PARAMS]`

Commands:

- `-r [NAME] [MASTER]` - recalls the password of NAME, pushing it to the
clipboard.

- `-p [NAME] [MASTER]` - recalls the password of NAME, printing it to stdout.

- `-s [NAME] [SEED] [MASTER]` - changes the seed for NAME.

- `-m [NEWMASTER] [REPEATNEWMASTER] [OLDMASTER]` - changes the master password.

- `-h [INPUT]` - hashes INPUT (but does not do full password processing, only
md5) and prints it WITH a new line.

- `-i [INPUT]` - hashes INPUT (but does not do full password processing, only
md5) and prints it WITHOUT a new line. This is used in the initialization step.

-  `-H or --help` - prints the help message.

If the user provides a flag, but not enough arguments, then the program will
request the missing arguments from stdin. When typing in the master password,
echo is disabled for stdin do prevent people near you from seeing your password,
just like `sudo` or `su`.

NOTE: If you choose to pass your master password as
an argument, it will be visible.


Example Usage:
--------------

    $ doorman -r gnusocial mypass
	$

This would mean mypass was indeed your password and the password for gnusocial
would be pushed to the clipboard in xclip.

    $ doorman -r gnusocial notmypass
	doorman: Incorrect password
	$

This would mean notmypass was _not_ your password, there is no change to the
clipboard.

    $ doorman -r
	Password Name: gnusocial
	Master Password:
	$

This would be the same as the first, only having prompted for the missing
arguments to be fed from stdin.

    $ doorman -h hashthis
	df5f5e4c517baba6abb156b2b549cecc3a0e0cc6148f66814d956d41a1675820
	$

This just prints the hash of the input text given, only accepts one argument.

    $ doorman -s gnusocial seed masterpass
	$

Set the seed of gnusocial to seed, since master pass was correct.


What's Next:
------------

Features that I would like to include in the future:

- Passwords are saved with extra data: a bit that means 'literal', or recall
this password without processing, just return the seed.

- Passwords are saved also with a length setting, as some websites and services
unfortunatly require shorter passwords, you could tell doorman to cut the length
of the output to the desired length.

- Passwords can be set with 3 new options:
  - `c` - Cap: Make sure there is at least one capital letter in the output.
  - `s` - Symbol: Make sure there is at least one symbol, or special charater in
	the output.
  - `n` - Number: Make sure there is at least one number in the output.

These options will make check the password that has been generated with the
given seed and see if it meets these requirements, if not, it will not save the
password and return an error. Users could then try again with a new seed. I only
see a password failing this on rare occasions, and with very short lengths set;
however, I would like user to know for certain that the password is correct for
their needs.

Another big feature I am working on is some sort of remote access. Obviously,
users want to bring their passwords with them, and do not always have access to
their computer or their seeds. The idea would be the user could send an email
containing a valid doorman command via another computer or mobile phone to a
user configured email address. This would then parse the data from the email,
and send the proper doorman output. I have concerns about mobile phone providers
and email providers obtaining this information, so ideally, you would be setting
up your own mail server to handle the requests. The goal would be to make a
configuration file that allows people to easily set up their own doorman server
and run this themselves. This project is currently not high priority.
