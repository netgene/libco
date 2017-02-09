#!/usr/bin/perl -w 
use strict; 
use IO::Socket; 

main:
{
  return -1 if(@ARGV < 2);
    my $host = $ARGV[0]; 
    my $port = $ARGV[1];  
    my $sock = new IO::Socket::INET( PeerAddr => $host, PeerPort => $port, Proto => 'tcp'); 
    $sock or die "no socket :$!"; 
    my $msg;

    my $i = 1;
    while($i < 100)
    {
        $sock->send("hello srv");
        print "send:hello srv\n";
        $sock->recv($msg, 1024);
        print "recv:" . $msg . "\n";
        sleep 5;
	$i++;
    }
    close $sock;
}
