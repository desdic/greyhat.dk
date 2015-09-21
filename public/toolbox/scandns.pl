#!/usr/bin/perl

use warnings;
use strict;
use Net::IP;
use Net::DNS;

my $startrange = $ARGV[0];
my $endrange = $ARGV[1];

print "Scanning: $startrange - $endrange\n";

my $range = "$startrange-$endrange";
my $ip = new Net::IP ($range) || die;

my $dummy = "xyz.dk";

do {
	my $res = Net::DNS::Resolver->new( nameservers => [$ip->ip()], recurse=> 0, debug=> 0,);
#	$res->tcp_timeout(4);
	$res->udp_timeout(4);
	my $query = $res->search($dummy);
	if ($query) {
		print $ip->ip()." OPEN\n";
	} else {
		print $ip->ip()." CLOSED\n";
	}
} while (++$ip);
