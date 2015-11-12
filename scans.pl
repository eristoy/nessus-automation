#!/usr/bin/env perl 
#===============================================================================
#
#         FILE: login.pl
#
#        USAGE: ./host-info.pl  
#
#  DESCRIPTION: 
#
#      OPTIONS: ---
# REQUIREMENTS: ---
#         BUGS: ---
#        NOTES: ---
#       AUTHOR: Eric Stoycon (es), eric.stoycon@cgcginc.com
# ORGANIZATION: 
#      VERSION: 1.0
#      CREATED: 11/05/2015 11:18:59 AM
#     REVISION: ---
#===============================================================================

use strict;
use warnings;
use utf8;
use Config::Simple;
use Getopt::Std;
use File::Copy;
use POSIX;
use Data::Dumper;
use Net::SSL;
use Net::Nessus::REST;
use File::HomeDir;
use Date::Simple qw (today);


#SSL Self Cert Fix
BEGIN { $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0 }
#Get Config File
my $home    =   File::HomeDir->my_home;
my $cfile   =   "$home/bin/nes.cfg";
my $cfg     =   new Config::Simple($cfile);

#Setup Vars;

my $NURL    =   $cfg->param('NURL');
my $NUser   =   $cfg->param('NUser');
my $NPass   =   $cfg->param('NPass');
my $SMHost  =   $cfg->param('SMHost');
my $SMUser  =   $cfg->param('SMUser');
my $SMPass  =   $cfg->param('SMPass');
my $SMDom   =   $cfg->param('SMDom');
my $date    =   today();
my $format;
my $datediff;
my $odate;
my $m;

#Get CLI OPTIONS
my %options=();
getopts("hmf:d:", \%options);
if (!%options) {
    do_help();
}
if ($options{h}) {
    do_help();
}
if ($options{f} eq 'csv') {
        $format = $options{f};
    } elsif ($options{f} eq 'nessus') {
        $format = $options{f};
    } else {
        print "Invalid Format Option\n";
        do_help();
    }
if ($options{d} eq '') {
    do_help();
} else {
    $datediff=$options{d};
}
if (defined $options{m}) {
    $m="1";
} else {
    $m="0";
}



sub logon {
our $nessus = Net::Nessus::REST->new(
    url =>  $NURL
);
print "logging on\n";
$nessus->create_session(
    username    =>  $NUser,
    password    =>  $NPass
);

}

use vars qw( $nessus );

sub get_scan_ids {
    #print "Getting IDs\n";
    my @id;
    my $scans = $nessus->list_scans();
    foreach my $x (@{$scans->{'scans'}}) {
        push @id, "$x->{'id'},$x->{'status'},$x->{'name'},$x->{'last_modification_date'}";
        }
    return @id;
}

sub export_scan {
    #print "Exporting scan\n";
    my $sid = "$_[0]";
    my $fmt = "$_[1]";
    if ($sid eq '') {
        die "***Error EXpected <scan_id> <format>\n";
    }
    my $scan_export = $nessus->export_scan(scan_id => $sid, format => $fmt);
    return $scan_export;

}

sub get_export_status {
    #print "Getting status\n";
    my $sid = "$_[0]";
    my $fid = "$_[1]";
    if ($sid eq '') {
        die "***Error Expected <scan_id> <file_id>\n";
    }
    my $status = $nessus->get_scan_export_status(scan_id => $sid, file_id => $fid);
    if ($status ne "ready" ) {
        sleep(2);
        &get_export_status;
    };
}

sub download_scan {
    #print "Downloading file\n";
    my $sid = "$_[0]";
    my $fid = "$_[1]";
    my $file = "$_[2]";
    if ($sid eq '') {
        die "***Expected <scan_id> <file_id> <filename>\n";
    }
    my $dst_file = "$home/nessus/data/$file";
    my $dl_file = $nessus->download_scan(scan_id => $sid, file_id => $fid, filename => $dst_file);
}

sub do_move{
    my $user = $cfg->param('SMUser');
    my $pass = $cfg->param('SMPass');
    my $host = $cfg->param('SMHost');
    my $domain  = $cfg->param('SMDom');
    my $file = $_[0];
    my $src = "/root/nessus/data/$file";
    my $mnt = "/root/nessus/clt-fs";
    my $dst = "$mnt/Support/drop/";
    my $smbopt = "username=$user,workgroup=$domain,password=$pass";
    # print "Mounting on $mnt to copy from $src to $dst\n";
    my $size = -s $src;
    if ($size > '1020000') {
        print "Starting File Move\n";
        system('/bin/mount -t cifs //clt-fs/Shared$ /root/nessus/clt-fs -o username=eric.stoycon,workgroup=cgtechnology,password=Ncc1701-d');
            my $status = move("$src","$dst");
            if (!$status) {
                system('umount /root/nessus/clt-fs');
                die "Failed to copy $file $!\n";
        }
        system('umount /root/nessus/clt-fs');
       }
} 
sub logoff{
    $nessus->destroy_session();
}
sub do_help {
    print "Download Nessus Scan Exports. \n./get_scans.pl <options>\nOptions:\n\t\t-h\t\t:This Help Message\n\t\t-f\t\t:Export Format, csv or nessus\n\t\t-d\t\t:Previous Number of Days to Download\n\t\t-m\t\t:Move files to CLT-FS\n";
    exit 1; 
}

##Main
my @ScanList;
my @Scan;
my $export;
my $filename;
my $scan_date;
$odate = today() - $datediff;
logon;
#Get Scan IDs,
@ScanList = get_scan_ids();
foreach my $scans (@ScanList) {
    @Scan = split(/,/,$scans);
    my $scan_ID = "$Scan[0]";
    if ($Scan[1] eq 'completed') {
        $scan_date = strftime '%Y-%m-%d', localtime $Scan[3];
        if ($scan_date ge $odate) {
            $filename = "$Scan[2].$scan_date.$format";
            $export = export_scan($scan_ID,$format);
            get_export_status($scan_ID,$export);
            download_scan($scan_ID,$export,$filename);
            #Do move if set
            if ($m eq "1") {
                do_move($filename);
            }
        }
    }
}
logoff;
