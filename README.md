# saruman_v2

## Description

Saruman injects a dynamically linked PIE executable into a remote process image and creates
a thread of execution for it. This is an anti-forensics technique. Further improvements can be made
such as writing a custom loader to replace dlopen that specifically uses anonymous memory mappings.

## Build instructions

### Install libelfmaster

```
$ git clone git@github.com:elfmaster/libelfmaster
$ cd libelfmaster/src
$ make
$ sudo make install
```

### Build Saruman

```
$ cd saruman
$ make
```

### Usage

Specify the target pid of the process you want to inject into
Specify the path of the executable you want to run inside of the remote process
Specify the command line args of the program you are injecting
```
./saruman <target_pid> <exec_path> [args]
```


