#!/usr/bin/ruby
#
# These classes are used to calculate viable opcode windows and per-byte
# durations for a temporal address.
#
# skape
# mmiller@hick.org
# 08/2005
#

###
#
# TemporalAddressPermutation
# --------------------------
#
# This class represents a logical permutation for a given temporal address
# state.
#
###
class TemporalAddressPermutation

	def initialize(opts)
		self.simple   = opts['SimpleString']
		self.secs     = opts['Seconds']
		self.str      = opts['PrintableDate']
		self.bytes    = opts['Bytes']
		self.duration = opts['Duration']
		self.opcode   = opts['Opcode']
	end

	#
	# Returns the raw bytes that compose the temporal address state
	# as hex like:
	#
	# 0000000042c22b01
	#
	def bytes_to_s
		bytes.unpack('H*')[0]
	end

	#
	# Returns the duration of the permutation as a printable string.
	#
	def duration_to_s
		TemporalAddress.psplit(
			TemporalAddress.split_secs(duration))
	end

	#
	# Returns the printable date that this permutation will occur at.
	#
	def pretty
		str
	end

	#
	# Returns the permutation as a CSV.
	#
	def to_csv
		"#{simple},#{secs},#{str},#{bytes},#{opcode.unpack('H*')[0]},#{duration}"
	end

	attr_reader :simple, :secs, :str, :bytes, :duration, :opcode

protected
	
	attr_writer :simple, :secs, :str, :bytes, :duration, :opcode

end

###
#
# TemporalAddress
# ---------------
#
# This class is responsible for building a list of viable date 
# windows for a given temporal address based on the period, 
# scale, and capacity of the timer as passed to the constructor.
#
###
class TemporalAddress

	#
	# Initializes the instance with the capacity, period, and
	# scale of the temporal address.
	#
	def initialize(capacity, period, scale = "abs1970")
		self.base_time = 0
		self.capacity  = capacity.to_i
		self.period    = period
		self.scale     = scale
		self.intv      = nil
		self.tosec     = Proc.new { |rawtime| 
			secs = (rawtime.to_f / period.to_f).to_i
		}

		self.on_permutation_proc = nil
	end

	#
	# Returns the time intervals of each byte position in terms of
	# how much time it takes for them to change values.
	#
	def intervals
		return self.intv if (self.intv)

		self.intv = []

		# Starting at byte index 0 and going up to the capacity of
		# the temporal address minus one...
		0.upto(capacity - 1) { |pos|

			# Calculate the amount of time it takes for the byte at this position
			# to change.
			self.intv << ((256 ** pos).to_f / period.to_f).to_i
		}

		self.intv
	end

	#
	# Returns all of the intervals on a per byte basis (how long they take to
	# change).
	#
	def intervals_to_s
		str = "\nInterval of time it takes to change each byte:\n\n"

		intervals.each_with_index { |ints, pos|
			intv = split_secs(ints)

			str += "#{pos.to_s.rjust((capacity-1).to_s.length)}: #{psplit(intv)}\n"
		}

		str += "\n"
	end

	#
	# Calculate viable date ranges for a given set of opcodes.  If a block
	# is passed, permutations are passed unsorted one at a time.  This can
	# be useful if there is a large data set that would be expensive to
	# store completely in memory at one time.
	#
	def generate(*opcodes, &block)
		perms = []

		# For each of the supplied opcodes...
		opcodes.sort.each { |opcode|
			# Start at the first viable byte (the one with a duration that
			# would be useful for exploitation) and go up until the capacity
			# of the temporal address minus one...
			start_byte.upto(capacity - 1) { |off|
				nsecs = 0
				idx   = 0

				# Skip opcodes that wont fit
				next if (off + opcode.length > capacity)

				# Calculate the base value using the individual byte values of
				# the current opcode.
				opcode.each_byte { |b|
					nsecs += value_at_offset(off + idx, b)
					idx   += 1
				}

				# If there's room after the opcode to permutate non-opcode bytes,
				# kick off that permutation.
				if (off + opcode.length < capacity)
					generate_permutations(perms, opcode, nsecs, off + opcode.length, off, &block)
				# Otherwise, finalize the current permutation and add it to the 
				# list of permutations if it's valid.
				else
					if ((perm = finalize_permutation(nsecs, opcode, off - 1)))
						if (on_permutation_proc)
							on_permutation_proc.call(perm)
						else
							perms << perm 
						end
					end
				end
			}
		}

		# Return the sorted list of permutations, or an empty set if a block
		# was passed.
		perms.sort { |a,b| a.secs <=> b.secs }
	end

	#
	# Returns seconds, minutes, hours, days, and years from the
	# supplied seconds.
	#
	def self.split_secs(seconds)
		[ 31536000, 86400, 3600, 60, 1 ].map{ |d| 
			if ((c = seconds / d) > 0)
				seconds -= c.truncate * d
				c.truncate
			else
				0
			end
		}.reverse
	end

	#
	# Returns the string representation of the supplied cycle.
	#
	def self.psplit(cycv)
		str = ''

		[ "sec", "min", "hour", "day", "year" ].each_with_index { |name, idx|
			next if (!cycv[idx] or cycv[idx] == 0)

			str = "#{cycv[idx]} #{name + ((cycv[idx] != 1) ? 's' :'')} " + str
		}

		str.length > 0 ? str : "<1 sec"
	end

	#
	# Instance alias for the class method.
	#
	def split_secs(secs)
		self.class.split_secs(secs)
	end

	#
	# Instance alias for the class method.
	#
	def psplit(cycv)
		self.class.psplit(cycv)
	end

	attr_accessor :tosec
	attr_accessor :base_time
	attr_accessor :on_permutation_proc

protected

	#
	# Walks all the byte permutations at a given offset using the 
	# supplied opcode array.
	#
	def generate_permutations(perms, opcode, base_nsec, off, opcode_off)
		# For each byte value
		0.upto(256) { |bval|
			# Add the value of the byte value at the supplied offset to the
			# base time.
			curr = base_nsec + value_at_offset(off, bval)	

			# If there's still room left for another byte value permutation,
			# call ourself again with the offset incremented by one and the
			# current value used as the base number time.
			if (off + 1 < capacity)
				generate_permutations(perms, opcode, curr, off + 1, opcode_off)
			end

			# Regardless, finalize the permutation at this byte value and append
			# it to the supplied list if it's valid.
			if ((perm = finalize_permutation(curr, opcode, opcode_off - 1)))
				if (on_permutation_proc)
					on_permutation_proc.call(perm)
				else
					perms << perm 
				end
			end
		}
	end

	#
	# Finalize a permutation by splitting it into its various attributes,
	# such as time of occurrence, the byte state when it occurs, the opcode
	# that existing within it, the duration of the window, and so on.
	#
	def finalize_permutation(rawtime, opcode, duration_off)
		# Convert the raw time value to seconds and convert it to
		# 1970 epoch time if an absolute date scale is being used.
		secs = tosec.call(rawtime) - convert_scale_to_1970

		# If the temporal address has an absolute scale and the number
		# of seconds are less than the base time, then we exclude it.
		if (scale =~ /^abs/ and secs < base_time)
			return nil
		end

		# If the duration offset added to the opcode length is greater
		# than the capacity of the temporal address, then this is an
		# invalid permutation and we should ignore it.
		if (duration_off + opcode.length >= capacity)
			return nil
		end

		# Depending on the capacity, convert the rawtime into a ruby
		# integer.  This supports arbitrarly large capacities.
		raw  = ''
		cp   = capacity

		while (cp > 0)
			raw      += [ rawtime & 0xffffffff ].pack('V')
			rawtime >>= 32
			cp       -= 4
		end

		begin
			first = str = ''

			# If the temporal address has an absolute scale, figure out
			# what date it's associated with.
			if (scale =~ /^abs/)
				t = Time.at(secs)

				# Eliminate daylight savings time by default.
				if (t.isdst == true)
					t = Time.at(secs - 3600)
				end

				str   = t
				first = "#{t.mon}/#{t.year}"
			else
				str   = psplit(split_secs(secs))
				first = secs.to_s
			end

			# Create a temporal address permutation instance and return it
			# to the caller.
			return TemporalAddressPermutation.new(
				'SimpleString'  => first, 
				'Seconds'       => secs, 
				'PrintableDate' => str, 
				'Bytes'         => raw,
				'Duration'      => intervals[duration_off+1],
				'Opcode'        => opcode)
		rescue
		end

		nil
	end

	#
	# Returns the value of a character at an offset.
	#
	def value_at_offset(off, chr)
		((256 ** (off)) * chr)
	end


	#
	# Adjustment of time to get to 1970.
	#
	def convert_scale_to_1970
		case scale
			when 'abs1601'
				11644473600
			when 'abs1970'
				0
			else
				0
		end
	end

	#
	# Finds the first viable byte to scan from that changes less frequently
	# than a defined interval, default 60 seconds.
	#
	def start_byte(change_intv = 60)
		intervals.each_with_index { |s, idx|
			return idx if (s >= change_intv)
		}
		nil
	end

	attr_accessor :capacity, :period, :scale, :intv

end
