#!/usr/bin/env perl 
#===============================================================================
#
#         FILE: get_all_scans.pl
#
#        USAGE: ./get_all_scans.pl  
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
#      CREATED: 10/20/2015 10:28:09 AM
#     REVISION: ---
#===============================================================================

use strict;
use warnings;
use utf8;
use LWP;
use LWP::UserAgent;
use JSON;
use Data::Dumper;
use Net::SSL;
use Date::Simple qw (today);
use POSIX;
use Getopt::Std;
use File::Copy;
use File::HomeDir;
use Config::Simple;



# Self signed cert fix
BEGIN { $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0 }

# config var
my $cfg = new Config::Simple('nes.cfg');
my $baseurl     = $cfg->param('NURL');
my $user        = $cfg->param('NUser');
my $pass        = $cfg->param('NPass');;
my $date        = today();
my $home        = File::HomeDir->my_home;
my $format;
my $datediff;
my $odate;
my $m;
#Get CLI Options
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
#create user agent
my $ua = LWP::UserAgent->new(keep_alive => 1);
$ua->agent("OCS/5.1");

sub login {
    my $req = HTTP::Request->new(POST => $baseurl . 'session');
    $req->content_type('application/json; charset=UTF-8');

    my $json = '{
    "username": "'.$user.'",
    "password": "'.$pass.'"
    }';
    $req->content($json);
    our $res = $ua->request($req);
    #check if login worked and get session token
    our $NessusToken;
    if ($res->is_success) {
        my $result = from_json($res->content);
        $NessusToken = $result->{'token'};
    } else {
        print "Login failed or failed to get token\n";
        exit;
    };
    #update headers with token
    our $h = new HTTP::Headers;
    $h->header('X-Cookie' => "token=$NessusToken;");

}

use vars qw( $res $NessusToken $baseurl $h );
sub do_help {
    print "Download Nessus scan exports.\n./get_all_scans.l <options>\nOptions:\n\t\t-h\t\t:This Help Message\n\t\t-f\t\t:Export Format, csv or nessus\n\t\t-d\t\t:Previous Number of Days to download\n";
    exit 1;
}
sub get_scans {
    # List the scans
    my @scanlist;
    my $req = HTTP::Request->new('GET', $baseurl . 'scans' , $h);
    $req->content_type('application/json; charset=UTF-8');
    $res = $ua->request($req);
    if (!$res->is_success) {
        warn $res->status_line . "\n";
        warn $res->content . "\n";
        exit
    }
   my $scandata = from_json($res->content);
    foreach my $x (@{$scandata->{'scans'}}) {
        push @scanlist, "$x->{'id'},$x->{'status'},$x->{'name'},$x->{'last_modification_date'}";
    } 
   return @scanlist;
}

sub get_historyID {
    #check if ID was passed
    my @hdata;
    my $s_id = "$_[0]";
    if ($s_id eq '') {
        warn "\n*** ERROR: Expected <scan_id> \n\n";
        die;
   };
    my $req = HTTP::Request->new('GET', $baseurl . "scans/$s_id" , $h);
    $req->content_type('application/json; charset=UTF-8');
    $res = $ua->request($req);
    #Fail test
    if (!$res->is_success) {
        warn $res->status_line ."\n";
        warn $res->content . "\n";
        exit
    }
    my $historydata = from_json($res->content);
    foreach my $x (@{$historydata->{'history'}}) {
        push @hdata, $x->{'history_id'};
    }
    return @hdata;
}

sub get_scan_export {
    # Check if scan_id was passed
    if ($_[1] eq '') {
        warn "\n*** ERROR: Expected <scan_id> <history_ID> \n\n";
        die;
    };

    print "\n*** Exporting Scan ID $_[0] To $_[2] Format with history ID $_[1] \n";

    # Post to (/scans)
    my $req = HTTP::Request->new('POST' , $baseurl . "scans/${_[0]}/export" , $h);
    $req->content_type('application/json; charset=UTF-8');

    # Generate the JSON POST data.
    my $json = '{
        "format": "'.$_[2].'",
        "history_id": "'.$_[1].'"
    }';

    # Populate the BODY with JSON encoded data.
    $req->content($json);

    # Send the request
    $res = $ua->request($req);
    #print Dumper($req);

    # Test for failure
    if (!$res->is_success) {
        warn $res->status_line . "\n";
        warn $res->content . "\n";
        exit
    }

    # Convert JSON data to Perl data structure
    my $postdata = from_json($res->content);
    #print "*** Exported to file ID: $postdata->{'file'} \n";
    #print "$postdata->{'file'} \n";

    # Set a variable for later use.
    our $exportID=$postdata->{'file'};
}

sub get_export_status {
    use vars qw( $exportID );
     my $req = HTTP::Request->new('GET' , $baseurl . "scans/${_[0]}/export/${exportID}/status" , $h);
    $req->content_type('application/json; charset=UTF-8');

    # Send the request to the server
    $res = $ua->request($req);

    # Test for failute
    if (!$res->is_success) {
        warn $res->status_line . "\n";
        warn $res->content . "\n";
        exit
    }

    my $exportstatus = from_json($res->content);

    print "*** Current Export Status: $exportstatus->{'status'} \n";

    if ($exportstatus->{'status'} ne "ready") {
        sleep(2);
        &get_export_status;
    };
}
sub get_scan_download {
    my $req = HTTP::Request->new('GET' , $baseurl . "scans/${_[0]}/export/${_[1]}/download" , $h);
    $req->content_type('application/json; charset=UTF-8');
    $res = $ua->request($req);
    if (!$res->is_success) {
        warn $res->status_line . "\n";
        warn $res->content . "\n";
        exit
    }
    if ($_[1] eq '') {
        warn "\n** Error Expected <scan_id> <output_file> \n\n";
        die;
    }
    my $dst_file = "$home/nessus/data/$_[2]";
    open (FILE, "> $dst_file") or error_msg("Failed to write report file $_[2]: $!");
    print FILE $res->content;
    close FILE;
}
sub do_move {
    my $user = $cfg->param('SMUser');
    my $pass = $cfg->param('SMPass');
    my $host = $cfg->param('SMHost');
    my $domain  = $cfg->param('SMDom');
    my $file = $_[0];
    my $src = "$home/nessus/data/$file";
    my $mnt = "/$home/nessus/clt-fs";
    my $dst = "$mnt/Support/drop/";
    #print "Mounting on $mnt to copy from $src to $dst\n";
    #system('/bin/mount -t cifs //clt-fs/Shared$ /root/nessus/clt-fs -o username=eric.stoycon,workgroup=cgtechnology,password=Ncc1701-c');
    system('/bin/mount -t cifs //'.$host.'/Shared$ '.$home.'/nessus/clt-fs -o username='.$user.',workgroup='.$domain.',password='.$pass.'');
    if ($? == -1 ) {
        die "Failed to mount: $!\n";
    } 
    elsif ( $? & 127) {
        printf "child died with signal %d, %s coredump\n",
    ($? & 127),  ($? & 128) ? 'with' : 'without';
    die;
    } else {
        my $status = move("$src","$dst");
          if (!$status) {
        die "Failed to copy $file $!\n";
        }
        system('umount '.$home.'/nessus/clt-fs');
    }
}

sub logoff {
    # Post to (/session)
    my $req = HTTP::Request->new('DELETE' , $baseurl . "session" , $h);
    $req->content_type('application/json');

    # Send the request
    $res = $ua->request($req);

    # Test for failure
    if (!$res->is_success) {
        warn $res->status_line . "\n";
        warn $res->content . "\n";
        exit
    }
}

#MAIN
my @ScanList;
my @Scan;
my (@hid,@sorted_hid);
my $h_id;
my $export;
my $filename;
my $scan_date;

#get date diff
$odate = today()- $datediff;
login;
#Get Scan IDs

@ScanList = get_scans();
foreach my $scans (@ScanList) {
   @Scan = split(/,/,$scans);
   if ($Scan[1] eq 'completed') {
        $scan_date = strftime '%Y-%m-%d', localtime $Scan[3];
        if ($scan_date ge $odate) {
            $filename = "$Scan[2].$scan_date.$format";
            @hid = get_historyID($Scan[0]);
            @sorted_hid = sort {$a <=> $b } @hid;
            $h_id = $sorted_hid[-1];
            $export = get_scan_export($Scan[0],$h_id,$format);
            get_export_status($Scan[0]);
            get_scan_download($Scan[0],$export,$filename);
            #Do File move if set
            if ($m eq "1") {
                do_move($filename);
            }
            
   }
   }
   
}
logoff;
