#!/usr/bin/perl

# makedumpfile-R.pl
#
# Copyright (C) 2007, 2008  NEC Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

$name_dumpfile = @ARGV[0];
$TRUE  = 1;
$FALSE = 0;
$MAKEDUMPFILE_SIGNATURE = "makedumpfile";
$MAX_SIZE_MDF_HEADER = 4096;
$TYPE_FLAT_HEADER = 1;
$END_FLAG_FLAT_HEADER = -1;

print "Start re-arranging dump data of flattened format to a dumpfile.\n";
open(FILE_DUMPFILE, ">$name_dumpfile") || die "Cannot open $name_dumpfile.\n";
binmode(FILE_DUMPFILE);

$value_64bits = &is_64bits_system;

if (&rearrange_dumpdata == $TRUE) {
	printf "The dumpfile is saved to $name_dumpfile.\n";
	printf "Completed.\n";
} else {
	printf "Failed.\n";
}
close(FILE_DUMPFILE);
# End


# Re-arrange dump data of flattened format from a standard input.
sub rearrange_dumpdata {
	if (&read_start_flat_header != $TRUE) {
		return $FALSE;
	}
	if ($value_64bits == $TRUE) {
		$ret_seek = &seek_for_64bits_system();
	} else {
		$ret_seek = &seek_for_32bits_system();
	}
	$buf_size = &get_buf_size();
	while (($ret_seek == $TRUE) && (0 < $buf_size)) {
		&read_buf_from_stdin($buf_size);
		if (syswrite(FILE_DUMPFILE, $buf, $buf_size) != $buf_size) {
			print "Cannot write. $buf_size\n";
			return $FALSE;
		}
		if ($value_64bits == $TRUE) {
			$ret_seek = &seek_for_64bits_system();
		} else {
			$ret_seek = &seek_for_32bits_system();
		}
		$buf_size = &get_buf_size();
	}
	if (($ret_seek != $END_FLAG_FLAT_HEADER) || ($buf_size != $END_FLAG_FLAT_HEADER)) {
		print "Cannot get valid end header of flattened format.\n";
		print "ret_seek = $ret_seek, buf_size = $buf_size\n";
		return $FALSE;
	}
	return $TRUE;
}

sub read_start_flat_header {
	&read_buf_from_stdin($MAX_SIZE_MDF_HEADER);
	if (index($buf, $MAKEDUMPFILE_SIGNATURE) != 0) {
		print "It is not flattened format.\n";
		return $FALSE;
	}
	return $TRUE;
}

sub seek_for_64bits_system {
	my $value = 0;
	my ($high, $low) = &read_64bits;

	$value = &convert_2values_to_1value($high, $low);
	if ($value < 0) {
		return $value;
	}
	if (seek(FILE_DUMPFILE, $value, 0) == 0) {
		print "Cannot seek.\n";
		return $FALSE;
	}
	return $TRUE;
}

sub seek_for_32bits_system {
	my ($high, $low) = &read_64bits;

	# On 32bits system, a normal value cannot explain the offset of
	# large file(4GB or larger). For solving this problem, BigInt
	# module is used. But this module makes speed down.
	use Math::BigInt;
	local $value = Math::BigInt->new(1);

	if ($high < 0x80000000) {
		$value->blsft(32);
		$value->bmul($high);
		$value->badd($low);
	} else {
		# Negative value
		$low  = ($low ^ 0xffffffff);
		$high = ($high ^ 0xffffffff);
		$value->blsft(32);
		$value->bmul($high);
		$value->badd($low);
		$value->badd(1);
		$value->bneg();
	}
	if ($value < 0) {
		return $value;
	}
	if (seek(FILE_DUMPFILE, $value, 0) == 0) {
		print "Cannot seek.\n";
		return $FALSE;
	}
	return $TRUE;
}

# Get buf_size of flattened data header.
sub get_buf_size {
	my ($high, $low) = &read_64bits;
	return &convert_2values_to_1value($high, $low);
}

# Convert 2 values to 1 value.
#   This function should be called only if a value isn't over the size
#   of system value.
sub convert_2values_to_1value {
	my ($high, $low) = (@_[0], @_[1]);
	my $value = 0;
	if ($high < 0x80000000) {
		$value = $high * (1 << 32) + $low;
	} else {
		# Negative value
		$low  = ($low ^ 0xffffffff);
		$high = ($high ^ 0xffffffff);
		$value = (-1) * ($high * (1 << 32) + $low + 1);
	}
	return $value;
}

# Get 64bits of dump data.
#   This function returns 2 values because a value of 32bits system cannot
#   explain 64bits.
sub read_64bits {
	my ($high, $low) = (0, 0);
	&read_buf_from_stdin(8);

	# Separate 2 values because hex() cannot support 64bits on 32bits system.
	my ($value1, $value2) = unpack("H8 H8", $buf);
	$value1 = hex($value1);
	$value2 = hex($value2);
	if (is_bigendian() == $TRUE) {
		$low = $value1;
		$high = $value2;
	} else {
		$low = $value2;
		$high = $value1;
	}
	return ($high, $low);
}

# Get dump data of flattened format from a standard input.
sub read_buf_from_stdin {
	my $buf_size = @_[0];
	my $read_size = 0;
	while ($read_size < $buf_size) {
		$read_size += sysread(STDIN, $buf, $buf_size - $read_size, $read_size);
	}
}

# Check 64/32bits system.
sub is_64bits_system {
	my $temp1 = 1 << 31;
	my $temp2 = 1 << 33;
	if ($temp1 < $temp2) {
		return $TRUE;
	}
	return $FALSE;
}

# Check big/little endian.
sub is_bigendian {
	my $value = pack("l", 1234);
	$value = unpack("n", $value);
	if ($value == 1234) {
		return $TRUE;
	}
	return $FALSE;
}

