BeEF Injection Framework 
Ryan Linn <rlinn@trustwave.com>
Steve Ocepek <socepek@trustwave.com>

http://www.spiderlabs.com


INTRODUCTION
============

These tools can be used with the BeEF Framework to easily execute
MITM attacks. It includes the following tools:

shank.rb 					Stateful ARP poisoner, L2 forwarder, Lover, JS injector
autorun.rb  			Launches BeEF modules automatically based on events
dump_mod_info.rb	Lists all modules available for use with autorun
dump_results.rb 	Parses JSON variables produced by autorun.rb and queries
									BeEF backend


REQUIREMENTS
============

BeEF Framework (latest)
Ruby 1.9
PacketFu (latest)


USAGE
=====

1. Launch BeEF

2. Launch shank.rb

ruby shank.rb network

where "network" is a valid CIDR address
NOTE: Ensure that ip_forwarding is DISABLED

3. Launch autorun.rb

ruby autorun.rb

shank.rb will monitor the specified network for new devices and
perform ARP poisoning against each. shank.rb will perform L2
packet forwarding for each packet not destined for itself. HTTP
packets will be modified to include BeEF javascript.

Once hooked, autorun.rb takes care of launching attack modules
against the client automatically. This module will also instruct
shank to discontinue HTTP modification, since the target system
has now been hooked in BeEF.

COPYRIGHT
=========

BeEF Injection Framework
Created by Ryan Linn and Steve Ocepek
Copyright (C) 2012 Trustwave Holdings, Inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
