## Devilish Syscalls
The syscalls in Linux are just entries of a table in memory with pointers to their respective locations. Those pointers can be reassigned.
For example read can be swapped to write :^)

### Quirks
* To edit the syscall table we need to find it from the memory first. Doing this from the module itself is going to be somewhat tricky.
* The table resides in a read-only part of the memory (for rather obvious reasons), so in order to actually edit it we have to mark that area writable.

### State
* It works on my machine
