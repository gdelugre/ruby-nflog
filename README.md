Description of nflog
--------------------

nflog is a wrapper around libnetfilter\_log for Ruby. 

For example, you can receive captured packets for the NFLOG group 1:

```ruby
require 'nflog'

Netfilter::Log.create(1) do |packet|
    link, data = packet.data

    puts "Timestamp: #{packet.timestamp}"
    puts "Prefix: #{packet.prefix}"
    puts "UID: #{packet.uid}"
    puts "GID: #{packet.gid}"
    puts "Interface: #{packet.indev_name}"
    puts "Physical interface: #{packet.phys_indev_name}"
    puts "Ethernet: #{link.unpack("H*")[0]}" 
    puts "Payload: #{data.unpack("H*")[0]}" 
end
```

Dependencies
------------

You need to have kernel support for NFLOG and libnetfilter\_log installed to get it working.
nflog depends on nfnetlink and ffi (https://github.com/ffi/ffi/wiki/)


Contact
-------

Guillaume Delugré, guillaume at security-labs dot org
