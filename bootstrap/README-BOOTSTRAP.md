The bootstrap code is a userland-exec implementation that I wrote for Shiva
originally. It is very close to the Linux kernels implementation, and presently it
maps the PIE with file-backed mmaps' rather than anonymous... this is good for Shiva
but not so good for an anti-forensics tool, so perhaps I will change that :)
Anonymous mapping version is slightly easier anyways.

The bootstrap code is compiled into an ET_REL object and injected and relocated at runtime
by ./launcher
