#!/usr/bin/env ruby

=begin

= File
  nflog.rb

= Author
  Guillaume Delugré <guillaume AT security-labs DOT org>

= Info
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

=end


require 'rubygems'
require 'ffi'
require 'socket'
require 'nfnetlink'

module Netfilter

    #
    # Class representing a packet captured by Netfilter::Log.
    #
    class Packet

        class Timeval < FFI::Struct #:nodoc:
            layout :tv_sec, :ulong,
                :tv_usec, :ulong
        end

        class HardwareAddress < FFI::Struct #:nodoc:
            layout :hw_addrlen, :uint16,
                :__pad, :uint16,
                :hw_addr, [:uint8, 8]
        end

        def initialize(nflog, nfad)
            @nflog, @nfad = nflog, nfad
        end

        #
        # The netfilter mark.
        #
        def nfmark
            Log.nflog_get_nfmark(@nfad)
        end

        #
        # The packet timestamp.
        #
        def timestamp
            ptv = FFI::MemoryPointer.new :pointer
            tv = Timeval.new(ptv)
            if Log.nflog_get_timestamp(@nfad, ptv) < 0
                0
            else
                Time.at(tv[:tv_sec])
            end
        end

        #
        # The index of the interface the packet was received through.
        #
        def indev
            Log.nflog_get_indev(@nfad)
        end

        #
        # The name of the interface the packet was received through.
        #
        def indev_name
            get_interface_name(self.indev)
        end

        #
        # The index of the physical interface the packet was received through.
        #
        def phys_indev
            Log.nflog_get_physindev(@nfad)
        end

        #
        # The name of the physical interface the packet was received through.
        #
        def phys_indev_name
            get_interface_name(self.phys_indev)
        end

        #
        # The index of the interface the packet will be routed to.
        #
        def outdev
            Log.nflog_get_outdev(@nfad)
        end

        #
        # The name of the interface the packet will be routed to.
        #
        def outdev_name
            get_interface_name(self.outdev)
        end

        #
        # The index of the physical interface the packet will be routed to.
        #
        def phys_outdev
            Log.nflog_get_physoutdev(@nfad)
        end

        #
        # The name of the physical interface the packet will be routed to.
        #
        def phys_outdev_name
            get_interface_name(self.phys_outdev)
        end

        #
        # The source MAC address.
        #
        def hw_addr
            phw = Log.nflog_get_packet_hw(@nfad)
            return nil if phw.null?

            hw = HardwareAddress.new(phw)
            hw_addrlen = [ hw[:hw_addrlen] ].pack('v').unpack('n')[0]
            hw[:hw_addr].to_ptr.read_bytes(hw_addrlen)
        end

        #
        # The packet contents.
        #
        def data
            hwhdrlen = Log.nflog_get_msg_packet_hwhdrlen(@nfad)
            
            if hwhdrlen > 0
                hwhdr = Log.nflog_get_msg_packet_hwhdr(@nfad)
                link_header = hwhdr.read_bytes(hwhdrlen)
            else
                link_header = ''
            end

            payload_ptr = FFI::MemoryPointer.new(:pointer, 1)
            payload_size = Log.nflog_get_payload(@nfad, payload_ptr)
            if payload_size < 0
                raise LogError, "nflog_get_payload has failed"
            end

            payload = payload_ptr.read_pointer.read_bytes(payload_size)

            [ link_header, payload ]
        end

        #
        # The logging string.
        #
        def prefix
            logstr = Log.nflog_get_prefix(@nfad)
            raise LogError, "nflog_get_prefix has failed" if logstr.null?

            logstr.read_string
        end

        #
        # The NFLOG sequence number.
        #
        def seq
            seqnum = FFI::Buffer.new(FFI.type_size(FFI::Type::UINT32))
            if Log.nflog_get_seq(@nfad, seqnum) < 0
                raise LogError, "nflog_get_seq has failed"
            end

            seqnum.read_bytes(seqnum.total).unpack("I")[0]
        end

        #
        # The global NFLOG sequence number.
        #
        def seq_global
            seqnum = FFI::Buffer.new(FFI.type_size(FFI::Type::UINT32))
            if Log.nflog_get_seq_global(@nfad, seqnum) < 0
                raise LogError, "nflog_get_seq_global has failed"
            end

            seqnum.read_bytes(seqnum.total).unpack("I")[0]
        end

        #
        # The UID of the user that generated the packet.
        #
        def uid
            uid = FFI::Buffer.new(FFI.type_size(FFI::Type::UINT32))
            if Log.nflog_get_uid(@nfad, uid) < 0
                return 0
            end

            uid.read_bytes(uid.total).unpack("I")[0]
        end

        #
        # The GID of the user that generated the packet.
        #
        def gid
            gid = FFI::Buffer.new(FFI.type_size(FFI::Type::UINT32))
            if Log.nflog_get_gid(@nfad, gid) < 0
                return 0 
            end

            gid.read_bytes(gid.total).unpack("I")[0]
        end
        
        private

        def get_interface_name(index)
            iface = @nflog.net_interfaces[index]
            if iface
                iface[:name]
            end
        end

    end

    #
    # Module representing a Netfilter LOG interface.
    #
    class LogError < Exception; end
    class Log
        extend FFI::Library

        begin
            ffi_lib 'libnetfilter_log'
        rescue LoadError => exc
            STDERR.puts(exc.message)
            STDERR.puts "Please check that libnetfilter_log is installed on your system."
            abort
        end

        attach_function 'nflog_fd', [:pointer], :int
        attach_function 'nflog_open_nfnl', [:pointer], :pointer
        attach_function 'nflog_open', [], :pointer
        callback :nflog_callback, [:pointer, :pointer, :pointer, :buffer_in], :int
        attach_function 'nflog_callback_register', [:pointer, :nflog_callback, :buffer_in], :int
        attach_function 'nflog_handle_packet', [:pointer, :buffer_in, :int], :int
        attach_function 'nflog_close', [:pointer], :int
        attach_function 'nflog_bind_pf', [:pointer, :uint16], :int
        attach_function 'nflog_unbind_pf', [:pointer, :uint16], :int
        attach_function 'nflog_bind_group', [:pointer, :uint16], :pointer
        attach_function 'nflog_unbind_group', [:pointer], :int
        attach_function 'nflog_set_mode', [:pointer, :uint8, :uint32], :int
        attach_function 'nflog_set_timeout', [:pointer, :uint32], :int
        attach_function 'nflog_set_qthresh', [:pointer, :uint32], :int
        attach_function 'nflog_set_nlbufsiz', [:pointer, :uint32], :int
        attach_function 'nflog_set_flags', [:pointer, :uint16], :int
        attach_function 'nflog_get_msg_packet_hdr', [:pointer], :pointer
        attach_function 'nflog_get_hwtype', [:pointer], :uint16
        attach_function 'nflog_get_msg_packet_hwhdrlen', [:pointer], :uint16
        attach_function 'nflog_get_msg_packet_hwhdr', [:pointer], :pointer
        attach_function 'nflog_get_nfmark', [:pointer], :uint32
        attach_function 'nflog_get_timestamp', [:pointer, :buffer_out], :int
        attach_function 'nflog_get_indev', [:pointer], :uint32
        attach_function 'nflog_get_physindev', [:pointer], :uint32
        attach_function 'nflog_get_outdev', [:pointer], :uint32
        attach_function 'nflog_get_physoutdev', [:pointer], :uint32
        attach_function 'nflog_get_packet_hw', [:pointer], :pointer
        attach_function 'nflog_get_payload', [:pointer, :pointer], :int
        attach_function 'nflog_get_prefix', [:pointer], :pointer
        attach_function 'nflog_get_uid', [:pointer, :buffer_out], :int
        attach_function 'nflog_get_gid', [:pointer, :buffer_out], :int
        attach_function 'nflog_get_seq', [:pointer, :buffer_out], :int
        attach_function 'nflog_get_seq_global', [:pointer, :buffer_out], :int

        module CopyMode
            NONE = 0
            META = 1
            PACKET = 2
        end

        attr_reader :nflog_group
        attr_reader :net_interfaces

        #
        # Creates a new NFLOG userspace handler for _group_.
        #
        def initialize(group, mode = CopyMode::PACKET)
            @nflog_group = group
            @net_interfaces = Netfilter::Netlink.interfaces

            @nflog_handle = Log.nflog_open()
            raise LogError, "nflog_open has failed" if @nflog_handle.null?

            if Log.nflog_unbind_pf(@nflog_handle, Socket::AF_INET) < 0
                close
                raise LogError, "nflog_unbind_pf has failed"
            end

            if Log.nflog_bind_pf(@nflog_handle, Socket::AF_INET) < 0
                close
                raise LogError, "nflog_bind_pf has failed"
            end

            @nflog_group = Log.nflog_bind_group(@nflog_handle, group)
            if @nflog_group.null?
                close
                raise LogError, "nflog_bind_group has failed"
            end

            set_mode(mode)

            Log.nflog_callback_register(@nflog_group, method(:callback_handler), nil)
        end

        #
        # Changes the copy mode for the group.
        #
        def set_mode(mode, range = 0xffff_ffff)
            if Log.nflog_set_mode(@nflog_group, mode, range) < 0
                raise LogError, "nflog_set_mode has failed"
            end 
        end

        #
        # Changes the buffer size to stack log messages for this group.
        #
        def set_buffer_size(size)
            if Log.nflog_set_nlbufsiz(@nflog_group, size) < 0
                raise LogError, "nflog_set_nlbufsiz has failed"
            end
        end

        #
        # Changes the maximum number of NFLOG entries before packet are sent to userspace.
        #
        def set_queue_size(thres)
            if Log.nflog_set_qthresh(@nflog_group, thres) < 0
                raise LogError, "nflog_set_qthresh has failed"
            end 
        end

        #
        # Changes the maximum time for NFLOG to send packet to userspace.
        #
        def set_timeout(timeout)
            if Log.nflog_set_timeout(@nflog_group, timeout) < 0
                raise LogError, "nflog_set_timeout has failed"
            end
        end

        #
        # Processes logged packets, passing them through the provided callback.
        #
        def process(&callback)
            @callback = callback

            fd = Log.nflog_fd(@nflog_handle)
            raise LogError, "nfq_fd has failed" if fd < 0

            io = IO.new(fd)
            while data = io.sysread(4096)
                Log.nflog_handle_packet(@nflog_handle, data, data.size)
            end
        end

        #
        # Unbinds the log group.
        #
        def destroy
            Log.nflog_unbind_group(@nflog_group)
            close
        end

        #
        # Creates a new Log instance and binds onto a group with the provided callback.
        # The instance will be automatically destroyed at return.
        #
        def self.create(group, mode = CopyMode::PACKET, &callback)
            nflog = self.new(group, mode)
            nflog.process(&callback)
            nflog.destroy
        end

        private

        def callback_handler(nflog_group, nfmsg, nfad, data)
            packet = Packet.new(self, nfad)

            @callback[packet]
        end

        def close
            Log.nflog_close(@nflog_handle)
        end
    end
end
