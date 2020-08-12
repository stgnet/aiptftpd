# aiptftpd
Arbitrary IP TFTP Daemon
## Purpose
Some hardware may have a firmware recovery mode where it attempts
to load an update through TFTP from a fixed IP address.  Rather than
require the local computer to be statically assigned the necessary IP
address, this tool operates a simulated TFTP server on the IP address
and provides an ARP response to trick the device into using it.
## Arguments
* --ip=192.168.1.2 = IP address that the TFTP client will connect to
* --file=path/to/file = override the TFTP filename and supply an alternantive
## Example
Router wants to tftp "recovery.bin" from 192.168.1.88, but will be given
file "image.bin" instead:
* aiptftp --ip=192.168.1.88 --file=image.bin
