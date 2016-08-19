#!/usr/bin/env perl 
#===============================================================================
#
#         FILE: t.pl
#
#        USAGE: ./t.pl  
#
#  DESCRIPTION: 
#
#      OPTIONS: ---
# REQUIREMENTS: ---
#         BUGS: ---
#        NOTES: ---
#       AUTHOR: Eric Stoycon (es), estoycon@gmail.com
# ORGANIZATION: 
#      VERSION: 1.0
#      CREATED: 11/04/2015 03:19:52 PM
#     REVISION: ---
#===============================================================================

use strict;
use warnings;
use utf8;
use Net::SSL;
use Net::Nessus::REST;
use Data::Dumper;




#Self Signed cert fix
BEGIN { $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0 }

sub logon {
    our $nessus = Net::Nessus::REST->new(
        url => 'https://192.168.170.155:8834'
        );

        $nessus->create_session(
        username    =>  '',
        password    =>  ''
        );
}

use vars qw( $nessus );

sub get_scan_ids {
    my @sid;
    my $scans = $nessus->list_scans();
    foreach my $x (@{$scans->{'scans'}}) {
        push @sid, "$x->{'id'},$x->{'name'}";
    }
    return @sid;
}


#Main
my @sid;


logon;
@sid = get_scan_ids();

foreach my $n (@sid) {
    print $n."\n";;
}

#print "getting details\n";
    #
    #my $details = $nessus->get_scan_details(scan_id => $x->{'id'});
    #print Dumper($details);
    #print "Hosts for scan $x->{'name'}\n";
    #foreach my $i (@{$details->{'hosts'}}) {
    #        my $hn = $i->{'hostname'};
    #        my $hid = $i->{'host_id'};
    #        print "Hostname = $hn\nHost_ID $hid\n";
    #        my $h_details = $nessus->get_scan_host_details(scan_id => $x->{'id'}, host_id => $hid);
    #        print Dumper($h_details);
    #        exit;
    #}


#logoff;
