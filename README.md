# Msync protocol receiver validation tool

This project implements a simple MSYNC receiver according to the IETF draft: https://www.ietf.org/archive/id/draft-bichot-msync-04.txt
The tool allows to validate streams sent according to the MSYNC protocol.
The code is available here: https://github.com/Broadpeak-tv/Msync_validator_receiver.git

# Usage

Compile: 
```bash
make
```

Run help:
```bash
foo@bar:~$./msync_receiver -h
msync_receiver of msync protocol v3
   Usage: msync_receiver [-m multicast_address] <-r> <-l num_layers> <-p port> <-i interface_name> <-v>
       -m  Multicast IP address to receive MSync packet from
       -r  Use RTP as part of the transport multicast session protocol (default: no RTP)
       -l  How many "layers", e.g. multicast addresses, to receive (default 1, up to 10)
           IP addresses are incremented by one for each layer
       -p  Multicast port (default 6044)
       -i  Network interface to bind to
       -v  Verbose mode
```

# Licence
This code is licensed under the Apache License, Version 2.0 (the "License").
