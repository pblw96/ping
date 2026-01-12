# ICMP Ping Utility

A simple ICMP ping utility implemented in C++ using raw sockets. This program sends ICMP Echo Requests to a specified hostname and measures the round-trip time (RTT).

## Prerequisites
- Linux system
- Root privileges (required for raw sockets)

## Build and Run
```bash
g++ -o ping 
sudo ./ping <hostname>
```