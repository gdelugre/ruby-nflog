#!/usr/bin/env ruby

require 'nflog'

Netfilter::Log.create(1) do |packet|
    puts "Timestamp: #{packet.timestamp}"
    puts "Prefix: #{packet.prefix}"
    puts "UID: #{packet.uid}"
    puts "GID: #{packet.gid}"
    puts "Interface: #{packet.indev_name}"
    puts "Physical interface: #{packet.phys_indev_name}"
    puts
    link, data = packet.data

    puts "Ethernet: #{link.unpack("H*")[0]}" 
    puts "Payload: #{data.unpack("H*")[0]}" 
    puts '--'
end
