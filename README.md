# nf-pkd and friends

nf-pkd is a port knock detector with spa (single packet authorization).  I've tried to keep it compatible with iptr\_pkd while extending it's functionality. So any of the 1.0 and later ipt\_pkd knock clients should work with nf-pkd.

nf-pkd-knock is the knock generator/sender

## Running

Just fire it up!

Okay maybe not that easy but darn close.  In either order you can add, via netfilter or iptables, nfqueue rules to send data to the queue number you choose for nf-pkd to listen on and fire up nf-pkd.  It should be noted that any packets hitting the queue rules will be stalled if there is no listener for the queue, at least that is what it seemed like to me. *Turns out that is true, but you can add --queue-bypass and they'll pass to the next rule if there is no queue listener.*

Oh and you need a couple of rules telling it what to block.  Currently they are called actions but I really am thinking of changing that to rules, apologies ahead of time when/if that breaks someones setup in the future.

#### nf-pkd options
```
--queue N selecting which queue to associate with, default is 0
--actions path to the action files, default /etc/nf-pkd/actions.d
 ```
 nf-pkd --queue 3000 --actions /usr/local/etc/nf-pkd/actions.d

#### nf-pkd-knock options
```
--tag 4 byte tag to tell nf-pkd which rule(s) to look up
--host name or ip (ipv6 and ipv4 work) to send the knock packet to
--port port to send the knock packet to - random port 1-65535 chosen otherwise
--key shared key used in hashing - if not on the command line you'll get prompted for it password style
 ```

  nf-pkd-knock --host ::1 --port 22 --tag SSHK --key test

## nf-pkd rules/actions
nf-pkd actions are configured via json files.  They each contain a list of dicts describing keys and actions.
They should only be readable by root or the user that is running nf-pkd.

*Note: currently it only supports one action/rule per tag/port because of how it is mapped*
```
[
 {
  'name': <name>,
      string used for logging purposes so you can tell which rule was applied

  'key': <key>,
      Sets the shared key, it's up to 40 bytes long and can be
      entered in as hex by starting it with 0x.
      The remainder of the key is zero filled.

  'skew': <time-in-secionds>,
      Amount of skew +- to allow between the src/dst clocks.  Set to -1
      to ignore clock skew, for example if you have a virtual machine whose clock
      is continuously losing/gaining time. default is 10 seconds

  'window': <time-in-seconds>,
      Amount of time to allow new connections (tcp) or allow packets in general (udp)
      when this rule has been successfully knocked.

  'related': <time-in-seconds>,
      Number of seconds to allow related packets to pass after a connection is established for tcp.
      default is 0 - no time limit

  'tag': <tag>,
      Sets the tag for this knock key.  Use different tags for
      different keys on the same machine.  This speeds up processing
      as the knock doesn't have to be rehashed for every key check.
      Default tag is PKD0, the tag is up to 4 bytes and can be
      entered as hex by starting it with 0x.
      The remainder of the tag is zero filled.

  'reject': <drop, reset>,
      Sets the rejection type
      defaults to drop -- currently only drop is supported

  'protocol': <any, tcp, udp>,
      default any

  'port': <port number>
      number of the port that is being protected

  TODO: add this stuff
  'ext-command': <string of cmd + parameters to call if the rule matches>
  'ext-user': <user to run the ext-action command as>
  'obo': <bool> /* default false, allow OBO ips on this action */
 }
]
```
### Rule/Action examples
###### Block ssh ipv4 and ipv6 in general
*add nf-pkd queue to a chain*
```
iptables -A INPUT -p udp -j NFQUEUE --queue-num 0
ip6tables -A INPUT -p udp -j NFQUEUE --queue-num 0
```
*add nf-queue rules to direct the packets*
```
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j NFQUEUE --queue-num 0
ip6tables -A INPUT -p tcp --dport 22 -m state --state NEW -j NFQUEUE --queue-num 0
```
*nf-pkd rule file* -- actions.d/port22.json
```
[{'name': 'port22', 'port': 22, 'protocol': 'tcp', 'tag': 'SSHK', 'key': test, 'window': 60, 'skew': 10}]
```

###### Block ipv4 ssh and constrain knocks to a specific port
*constraining the knock ports can improve performance on machines that have other udp traffic (voip server).
It's also useful for reducing ports open on your firewall*

*add nf-pkd queue to a chain, use port 22 for knocking as well as ssh, bypass if no queue listener*
```
iptables -A INPUT -p udp --dport 22 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j NFQUEUE --queue-num 0 --queue-bypass
```
*nf-pkd rule file* -- actions.d/knock_port22.json
```
[{'name': 'knock_port22', 'port': 22, 'protocol': 'tcp', 'tag': 'SSHK', 'key': test, 'window': 60}]
```
Knocking for this one would be something like:

 `nf-pkd-knock -tag SSHK -key test -port 22 --host localhost`

###### Block ipv4 ssh and limit length of an ssh session to 5 minutes
*add nf-pkd queue to a chain*
```
iptables -A INPUT -p udp -j NFQUEUE --queue-num 0
```
*Note the lack of --state in this one, forcing all ssh packets through nf-pkd*
```
iptables -A INPUT -p tcp --dport 22 -j NFQUEUE --queue-num 0
```

*'related' is the duration in seconds that the established,related ssh packets are allowed to flow*

*nf-pkd rule file* -- actions.d/port22_limited.json
```
[{'name': 'port22_limited', 'port': 22, 'protocol': 'tcp', 'tag': 'SSHK', 'key': 'test', 'window': 60, 'related': 300}]
```


###### This example totally doesn't work because the code isn't in place yet
Using it to restart a service (like apache), window in this case is just a timestamp validation so others don't capture and replay this packet.
*add nf-pkd queue to a chain*
```
iptables -A INPUT -p udp -j NFQUEUE --queue-num 0
[{'name': 'apache_restart', 'tag': 'APAK', 'key': '0xafbead963a', 'window': 60, action: 'service apache restart'}]
```


## Building
* Install your linux's libnetfilter-queue-dev package (might have a slightly different name)
* Install golang's dep if you don't already have it installed [Dep](https://github.com/golang/dep)
* make (at the top level) will build nf-pkd and nf-pkd-knock and copy them to the bin directory

*Note: The makefiles set their own GOPATH so it shouldn't matter where you unpack this code.*

Apparently you need golang version 1.9 at least to build this successfully.  ubuntu has a couple of options [golang-go](https://github.com/golang/go/wiki/Ubuntu).  I verified that the snap one works fine.  It might build in as low as 1.7 but it looks like runtime.KeepAlive had some issues in earlier versions.

## Installing
Currently nothing exciting, just copy the nf-pkd and nf-pkd-knock executables to whereever.  It should be noted that nf-pkd needs to run as root or have cap_net_admin capability set on it's executable.  Eventually I'll add deb and rpm recipes to make installable packages.

Make a directory for the rules/actions. The default is `/etc/nf-pkd/actions.d/`, put your rules/actions there in json files that end with `.json`

nf-pkd will attempt to read any files in that directory and it's sub-directories that have that ending/extension

## What's a Knock?

In this case it's a small udp packet that contains some information hashed with a shared key that provides a firewall filter information about what to do if the authorization matches.

* Tag 4 bytes - used for rule lookup
* Timestamp 8 bytes of epoch seconds - used for clock skew
* Random 12 bytes - used for mixing the hash
* sha256 hash - used to verify that the packet wasn't modified in flight, detecting replays, and authorization of the sender

It is compatible with [pkd](https://github.com/estabroo/pkd) 1.x and later

### Differences from pkd
* nf-pkd supports ipv6
* nf-pkd currently does not support sending icmp unreachables
* nf-pkd will eventually have more features like OBO (knocking for someone else) and triggering commands

### ToDo
- [] option to send icmp unreachable instead of just dropping the packet
- [] allow multiple actions per port, both tag and what
- [] triggers (that's the ext-command, ext-user stuff) to run stuff on an incoming knock
- [] OBO (on behalf of) - knocking for another host
- [] more protocols - sctp and such
- [] rpm and deb packaging
- [] apparmor for nf-pkd in above packaging
- [] cap_net_admin in above packaging - maybe also group access
- [] signal nf-pkd for reloading rules
- [] Get real logging, currently just dumps stuff to stdout
- [] fix the make oddity that sometimes requires you to call make twice after change - missing dependency?

###### This uses what now (other dependencies)
* my fork of go-filter-queue [go-netfilter-queue](https://github.com/AkihiroSuda/go-netfilter-queue)
* golang.org/x/crypto [crypto](https://godoc.org/golang.org/x/crypto)
* golang.org/x/sys [sys](https://godoc.org/golang.org/x/sys)
* google/gopacket [gopacket](https://github.com/google/gopacket/)
