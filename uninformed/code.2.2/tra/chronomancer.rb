#!/usr/bin/ruby -I.
#
# This utility calculates viable opcode windows for a given
# temporal address based on its scale, period, and capacity.
# Thanks to thief for his naming skillz :)
#
# skape
# mmiller@hick.org
# 08/2005
#
require 'opcodes'
require 'chronomancy'

#
# Displays usage information.
#
def usage
	str = "Usage: chronomancer [OPTIONS]\n\n" +
		"OPTIONS\n\n" +
		"\t-s <opt>      Sets the scale (counter, abs1601, abs1970) [default=abs1970]\n" +
		"\t-p <opt>      Sets the update period [default=1]\n" +
		"\t-c <opt>      Sets the capacity [default=4]\n" +
		"\t-a <opt>      Sets scale, period, and capacity using an alias (c-p-s)\n" +
		"\t-b <opt>      Sets the base time for permutations in seconds since 1970\n" +
		"\t-h            You're looking at it\n" +
		"\n" +
		"MODES\n\n" +
		"\t-i            Displays per-byte durations\n" +
		"\n" +
		"SUPPORTED ALIASES\n\n"
	
	aliases.keys.sort.each { |name|
		vals = aliases[name]

		str += "\t#{name.ljust(13)} Capacity: #{vals[2]}  Period: #{vals[3].ljust(7)}  Scale: #{vals[0]}\n"
	}

	puts str + "\n"
	exit 1
end

#
# Returns a hash of supported temporal address aliases.
#
def aliases
	{
		# 4 byte since 1970
		"4-1s-1970"    => [ "abs1970", 1,         4, "1sec"    ],
		"4-100ms-1970" => [ "abs1970", (10 ** 1), 4, "100msec" ],
		"4-10ms-1970"  => [ "abs1970", (10 ** 2), 4, "10msec"  ],
		"4-1ms-1970"   => [ "abs1970", (10 ** 3), 4, "1msec"   ],

		# 8 byte since 1970
		"8-1s-1970"    => [ "abs1970", 1,         8, "1sec"    ],
		"8-100ms-1970" => [ "abs1970", (10 ** 1), 8, "100msec" ],
		"8-10ms-1970"  => [ "abs1970", (10 ** 2), 8, "10msec"  ],
		"8-1ms-1970"   => [ "abs1970", (10 ** 3), 8, "1msec"   ],
		"8-100us-1970" => [ "abs1970", (10 ** 4), 8, "100usec" ],
		"8-10us-1970"  => [ "abs1970", (10 ** 5), 8, "10usec"  ],
		"8-1us-1970"   => [ "abs1970", (10 ** 6), 8, "1usec"   ],
		"8-100ns-1970" => [ "abs1970", (10 ** 7), 8, "100nsec" ],
		"8-10ns-1970"  => [ "abs1970", (10 ** 8), 8, "10nsec"  ],
		"8-1ns-1970"   => [ "abs1970", (10 ** 9), 8, "1nsec"   ],

		# 8 byte since 1601
		"8-1s-1601"    => [ "abs1601", 1,         8, "1sec"    ],
		"8-100ms-1601" => [ "abs1601", (10 ** 1), 8, "100msec" ],
		"8-10ms-1601"  => [ "abs1601", (10 ** 2), 8, "10msec"  ],
		"8-1ms-1601"   => [ "abs1601", (10 ** 3), 8, "1msec"   ],
		"8-100us-1601" => [ "abs1601", (10 ** 4), 8, "100usec" ],
		"8-10us-1601"  => [ "abs1601", (10 ** 5), 8, "10usec"  ],
		"8-1us-1601"   => [ "abs1601", (10 ** 6), 8, "1usec"   ],
		"8-100ns-1601" => [ "abs1601", (10 ** 7), 8, "100nsec" ],
		"8-10ns-1601"  => [ "abs1601", (10 ** 8), 8, "10nsec"  ],
		"8-1ns-1601"   => [ "abs1601", (10 ** 9), 8, "1nsec"   ],
	}
end

#
# Prints a comma separated permutation.
#
def pperm(p)
	puts "#{p.simple},#{p.secs},#{p.pretty},#{p.bytes_to_s},#{Opcodes.opcode_groups[p.opcode]},#{p.duration_to_s}"
end

scale     = "abs1970"
period    = 1
capacity  = 4
tasks     = { 'perms' => true }
base_time = Time.now.to_i

# No arguments?  Usage.
if (ARGV.length == 0)
	usage
end

# Evalulate arguments in a lame-ish fashion.
ARGV.each_with_index { |opt, idx|
	case opt
		# Scale
		when "-s"
			scale = ARGV[idx+1] || "abs1970"
		# Period
		when "-p"
			period = (ARGV[idx+1] || 0).to_i
		# Capacity
		when "-c"
			capacity = (ARGV[idx+1] || 0).to_i
		# Alias (scale, period, and capacity)
		when "-a"
			scale, period, capacity = aliases[ARGV[idx+1] || '']

			if (!scale or !period or !capacity)
				puts "Invalid alias: #{ARGV[idx+1] || ''}"
				exit
			end
		# Base time
		when "-b"
			base_time = (ARGV[idx+1] || 0).to_i
		# Display intervals
		when "-i"
			tasks['intervals'] = true
		# Help
		when "-h"
			usage
	end
}

# Error checking for cool kids.
if (capacity == 0)
	puts "Invalid capacity."
	exit 1
end

if (period == 0)
	puts "Invalid period."
	exit 1
end

# Create a new temporal address instance.
ta = TemporalAddress.new(capacity, period, scale)

# Set the base time
ta.base_time = (scale =~ /^abs/) ? base_time : 0

# Display intervals if requested.
if (tasks['intervals'])
	puts ta.intervals_to_s
	exit 0
end

# Generate all the permutations for this temporal address.
if (tasks['perms'])

	STDERR.puts(
		"\n" +
		"Generating permutations for:\n" +
		"\tPeriod  : #{period}\n" +
		"\tScale   : #{scale}\n" +
		"\tCapacity: #{capacity}\n" +
		((ta.base_time > 0) ? "\tBaseTime: #{Time.at(ta.base_time)}\n" : "") +
		"\n")

	# If the scale is measured against an absolute time, we can use the sorted
	# list of permutations returned from generate since this set should be
	# rather small in comparison to temporal addresses with counter scales.
	if (scale =~ /^abs/)
		perms = ta.generate(*Opcodes.opcodes)
	
		perms.each { |p|
			pperm(p)
		}
	# Otherwise, if it's a counter scale, use the block method as we will
	# most likely get a very large number of permutations.
	else
		ta.on_permutation_proc = Proc.new { |p|
			pperm(p)
		}

		ta.generate(*Opcodes.opcodes)
	end
end

0
