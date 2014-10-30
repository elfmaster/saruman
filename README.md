Saruman v0.1 (Ryan O'Neill) elfmaster@zoho.com

Type make to compile launcher (It will also try to compile a parasite.c file which
is for you too supply). Make sure your parasite executable is compiled -fpic -pie

./launcher <pid> <parasite_executable> <parasite_args, [arg1, arg2, argN]> 

NOTE: In this version Saruman doesn't yet support injecting a program that requires command line args
because it is early POC. So <parasite_args> will not actually accept args yet.

./launcher --no-dlopen <pid> <parasite_executable>

When using --no-dlopen it uses a more stealth technique of loading the executable
so that it doesn't show up as /path/to/parasite.exe in the /proc maps file.
Currently this has some bugs and won't work with more complex parasites (To be fixed)
