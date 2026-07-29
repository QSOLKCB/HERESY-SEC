# IPC slot management

The inherited HERESY-style fixed slot boundary is 32 slots (`0..31`). A request for
slot 32 is rejected before the matching allow rule can take effect.

