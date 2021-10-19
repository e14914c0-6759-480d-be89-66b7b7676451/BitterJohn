# BitterJohn
Server side infrastructure for RDA.

## Usage

```bash
./BitterJohn install
systemctl enable --now BitterJohn.serivce
```
```text
Host of Sweet Lisa: The Host fo SweetLisa. Such as "sweetlisa.tuta.cc".
Chat Identifier: It is the UUID of a group. Such as "e14914c0-6759-480d-be89-66b7b7676451".
Server Type: The scenes of the server to be used. Such as "Server" and "Relay".
Server Ticket: The ticket of the server. It should be unique for every servers.
Address to listen on: The local address to listen on. Such as "0.0.0.0:17821".
Host to show: The outer host to show. Such as "racknerd-1.us.bitterJohn.tuta.cc".
Port to show: The outer port to show. Such as "17821". It is useful for NAT machine.
Server Name to show: The server name to show in the subscription. Such as "[Direct] Azure Brazil 🍉🇧🇷".
```