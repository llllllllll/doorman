doorman
=======

A password manager written in haskell by Joe Jevnik.

Last updated: 20.10.2013

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

Required packages to run:

- `xclip` - The x clipboard, installed through your distro's package manager
(pacman,yum,apt-get...).

Required packages to compile (use cabal install):

- `sha` - The package needed for hashing.
- `bytestring` - Used for efficient file IO.

I compiled with: `$ ghc --make -O2 doorman.hs`

Initializing:
-------------

Run the included shell script like `# setup install` in the same directory as
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

Usage:
------

`Usage: [OPTION] [PARAMS]`

Commands:

- `-r [NAME] [MASTER]` - recalls the password of NAME, pushing it to the
clipboard.

- `-p [NAME] [MASTER]` - recalls the password of NAME, printing it to stdout.

- `-s[OPTS] [NAME] [LENGTH] [SEED] [MASTER]` - changes the seed for NAME with
options:
  - `c` - Capital: Make sure there is at least one capital letter in the output.
  - `s` - Symbol: Make sure there is at least one symbol, or special charater in
	the output.
  - `n` - Number: Make sure there is at least one number in the output.
  - `l` - Save the password litterally, only recall the "seed" without
	processing"
The length should be between 1 and 128. Going over 128 will still make passwords
that are 128 characters long.

- `-h [INPUT]` - hashes INPUT with a sha512 (but does not do full password
processing) and prints it.

- `-i [INPUT]` - hashes INPUT with a sha256 (but does not do full password
processing) and prints it.

- `-l [m | o] [PATHTONEWFILE] [MASTER]` - merges or overwrites the password
library with the new file provided. Merging uses the new file's seeds in the
case of a collision.

-  `-H or --help` - prints the help message.

- `-v or --version` - prints the version info.

If the user provides a flag, but not enough arguments, then the program will
request the missing arguments from stdin. When typing in the master password,
echo is disabled for stdin do prevent people near you from seeing your password,
just like `sudo` or `su`.

NOTE: If you choose to pass your master password as
an argument, it will be visible.


Example Usage:
--------------

    $ doorman -r test mypass
	$

This would mean mypass was indeed your password and the password for test
would be pushed to the clipboard in xclip.

    $ doorman -r test notmypass
	doorman: Incorrect password
	$

This would mean notmypass was _not_ your password, there is no change to the
clipboard.

    $ doorman -r
	Password Name: test
	Master Password:
	$

This would be the same as the first, only having prompted for the missing
arguments to be fed from stdin.

    $ doorman [joejev@Sheila doorman]$ doorman -h hashthis
	4944849cf0a7e73a7b5b46289ed1ab5b670491523a26c76ef242de6252f4c12c1c2db461ee093e09787113a73875f0c24b93bfdd1864c53dab6e00c09b6b214d
	$

This just prints the sha512 hash of the input text given, only accepts one
argument. the `-i` command prints a sha256 instead.

    $ doorman -s test 12 seed masterpass
	$

Set the seed of test to seed, since master pass was correct. The length of the
password that is recalled will be set to 12, this allows you to make your
password as long as a site or program will allow.


What's Next:
------------

Features that I would like to include in the future:

- [DONE]: Passwords are saved with extra data: a bit that means 'literal', or
recall this password without processing, just return the seed.

- [DONE]: Passwords are saved also with a length setting, as some websites and
services unfortunatly require shorter passwords, you could tell doorman to cut
the length of the output to the desired length.

- [DONE]: Passwords can be set with 3 new options:
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

[TODO]: Another big feature I am working on is some sort of remote access.
Obviously, users want to bring their passwords with them, and do not always have
access to their computer or their seeds. The idea would be the user could send
an email containing a valid doorman command via another computer or mobile phone
to a user configured email address. This would then parse the data from the
email, and send the proper doorman output. I have concerns about mobile phone
providers and email providers obtaining this information, so ideally, you would
be setting up your own mail server to handle the requests. The goal would be to
make a configuration file that allows people to easily set up their own doorman
server and run this themselves. This project is currently not high priority.
