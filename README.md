https://www.devdungeon.com/content/using-libpcap-c#load-pcap-file

https://www.geeksforgeeks.org/use-volatile-keyword-in-c/

https://en.cppreference.com/w/c/program/signal

https://www.geeksforgeeks.org/getopt-function-in-c-to-parse-command-line-arguments/

https://datatracker.ietf.org/doc/html/rfc1035

https://datatracker.ietf.org/doc/html/rfc3596                       



### Understanding the DNS Header Format

A DNS header ^[[1](#citace)] is a fixed-size structure (12 bytes) with the following layout:

| Bytes     | Field       | Description                                   |
|-----------|-------------|-----------------------------------------------|
| 0-1       | `id`        | Transaction ID (unique identifier for request/response pair) |
| 2-3       | `flags`     | Flags and response codes (QR, Opcode, AA, etc.) |
| 4-5       | `qdcount`   | Number of entries in the Question Section     |
| 6-7       | `ancount`   | Number of entries in the Answer Section       |
| 8-9       | `nscount`   | Number of entries in the Authority Section    |
| 10-11     | `arcount`   | Number of entries in the Additional Section   |

### Citace

[1] Lundrigan, Lewis. *Hands-On Network Programming with C: Learn socket programming in C and write secure and optimized network code*. O'Reilly Media, 2019. Accessed from [O'Reilly](https://www.oreilly.com/library/view/hands-on-network-programming/9781789349863/812dd5c5-0d22-4ccd-8faf-f339b416bb2e.xhtml).

