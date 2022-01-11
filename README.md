# WinExperimental
Windows development experiments. This repository contains a Visual Studio 2019 solution with several projects.

## ArgEnv
Displays command line arguments and environment variables.

## PCapFile
A simple library for creating packet dump files in PCAP format

## PacketDriver
A WFP (Windows Filtering Platform) callout driver that can copy or redirect packets to user space for capturing, analysis, or traffic filtration (when only some of redirected packets are returned to the kernel for further processing).

## PacketDriverTest
A simple program for testing `PacketDriver`. It supports both packet copy and redirection (with returning all packets unmodified to the kernel). It can optionally save packets in a PCAP file using library `PCapFile`.

## ZeroDriver
A kernel driver resembling UNIX `/dev/zero`. It discards any data written to it and produces an infinite stream for reading.

## ZeroDriverTest
A simple program for testing `ZeroDriver`.
