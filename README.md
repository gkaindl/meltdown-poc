# POC for meltdown/spectre

I just wanted to see if this really works, and it actually does. Scary!

It reads out the `TEST_PHRASE` using the timing attack (in its own process).

Alternatively, by changing the macro `TEST_IN_OWN_PROCESS` to 0, you can
specify an address and length on the command line, and output raw data to pipe
into `strings`. In this case, it uses Intel's TSX to prevent crashing when
attempting to access the mem location, just like the meltdown paper says.

Tested on OS X 10.12.6
