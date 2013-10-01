doorman
=======

A password manager written in haskell by Joe Jevnik.

Last updated: 30.9.2013

Purpose:
--------

The purpose of `doorman` is to allow users to generate and employ very strong
passwords for various applications and websites without requiring them to need
to remember them, or save them in plain text anywhere. `doorman` allows users to
to safely store only 'seeds' of passwords that must be combined with a master
password in order to retrieve the password for that given name. The master
password is only ever stored post-hash for comparison. Also, the files are all
owned by a new user, also named 'doorman', and only have rw permisions for that
user. the application runs under doorman's permissions, so the only access to
those files can come through the `doorman` application, or 'root'. `doorman` can
be invoked from any terminal, but the intended use is to be invoked from dmenu
or something simmilar, where a user wouldn't have to leave the password promt
screen to retrieve the password. This is also why the behavior is to push it
directly to the clipboard, as dmenu has no stdout.

Compiling:
----------

Required packages:

- `puremd5` - The package needed for hashing installed through `cabal install`.

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

note: You can change the password at anytime with:

    $ doorman -m [NEWPASSWORD] [OLDPASSWORD]


Usage:
------

`Usage: [OPTION] [PARAMS]`

Commands:

- `-r [NAME] [MASTER]` - recalls the password of NAME, pushing it to the
clipboard.

- `-p [NAME] [MASTER]` - recalls the password of NAME, printing it to stdout.

- `-s [NAME] [SEED] [MASTER]` - changes the seed for NAME.

- `-m [NEWMASTER] [OLDMASTER]` - changes the master password.

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
	000242dc7a5257e1f265578cdcc6c3fd
	$

This just prints the hash of the input text given, only accepts one argument.

    $ doorman -s gnusocial seed masterpass
	$

Set the seed of gnusocial to seed, since master pass was correct.
