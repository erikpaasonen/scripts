#!/usr/bin/perl -w
use strict;
use warnings;
use Getopt::Long;

#use DateTime;


###########################################################################################################
#
#This Perl Script is for providing the transcription of syslog files to APG format depending on the technologies.
#
# This script is compatible with :
#    - Fortinet Fortigate logs
#    - Cisco FWSM, ASA, PIX logs
#    - Sonicwall export from TCPdump
#    - Added Sales@Office log format.
#    - Juniper Netscreen format
#
##########################################################################################################
#
# Author            : Stephane PEREZ
# Current Version   : 3.1.13
#
##################################
#
# Revisions
#
# - Version 1.0     : Initial creation of the script
# - Version 1.1     : Added spport for ASA and PIX firewalls
# - Version 1.2     : Added sonicwall and partial safe@office (Andrea)
# - Version 1.3     : Add some optimisations and lisibility enhancements in the code. Catch error when the file format cannot be determine at first line.
# - Version 1.4     : Correct help message
# - Version 1.5     : Add Juniper Netscreen log format support corrected bug related to sonicwall support
# - Version 1.6     : Fix some bugs with incomplete lines in the source file
# - Version 1.7     : Add some error catch on empty lines at the top of the file.
# - Version 2.0     : Add TSS format output for historical rule usage analysis
# - Version 2.1     : Update Cisco log messages
# - Version 2.2     : Consider NAT in cisco log messages
# - Version 2.5	    : Review parsing algorithm to improve performance by about 30%
# - Version 2.7	    : Change TSS Output format to match new requirements from st_rule_usage_importer
# - Version 2.8     : Add support for Cisco ACL matching with log ID 106100
# - Version 2.9	    : Corrected NAT handling Bug and interface match for Cisco ACL log ID #106100
# - Version 2.9.1   : Fixed Bug for logID 106001 an 106006 for interface match.
# - Version 3.0     : Added filtering of syslog entries
# - Version 3.0.1   : Adding some comments for future tasks to support RFC 5424 syslog format.
# - Version 3.0.9   : Adding support for Syslog RFC 5424 time format
# - Version 3.1	    : Adding filtering capabilities for Firewall / Source-destination IP, IP, Time, Date, port
# - Version 3.1.1   : Adding filtering capabilities for APG based output to SonicWall, Fortinet, Juniper, Safe@office.
# - Version 3.1.2   : Adding filtering capabilities for ACL and interface (currently only for cisco)
# - Version 3.1.3   : Update help guidelines and correct some typos.
# - Version 3.1.4   : update log parser for Cisco to avoid some funny syslog server configurations.
# - Version 3.1.5   : Fixed some filtering bugs in the code were filters were not applied properly.
# - Version 3.1.7   : Adding filtering capabilities for Subnet and bug fix for invalid ip address verification.
# - Version 3.1.8   : Corrected debug bugs and help.
# - Version 3.1.9   : Adding possibility of entering output file name in the command line.
# - Version 3.1.10  : Corrected bug with funny file names.
# - Version 3.1.11  : Corrected bug of filtering parameters and filter applies to ACLs, Hostnames and Interfaces. Corrected bug of Netmask/Bitmask calculation and selection
# - Version 3.1.12  : Adding verification of files if the first line is not a syslog file.
# - Version 3.1.13  : Adding support for SRX log files for APG.
# - Version 3.1.14  : Add rule number filtering for SRX, corrected bug of filtering parameter definition.
# - Version 3.1.15  : Anonymising some of the IP addresses for public delivery.
#
#############################
#   TODO
#
# - Add RFC 5424 support for non Cisco device based logs.
# - Adding extended filtering capabilities with multiple IPs, subnets, ACLs or interface
# - Need to add Palo Alto log formats
# - Provide a more flexible and efficient architecture for adding devices using procedures to parse log entries
# - Add filtering IP addresses, ports from the CLI
# - Integrate with SecureTrack API for individual or multiple rule selection from the Firewall policy
#
##########
#
##################################

#Variable initialization;
#
#
use vars qw ($filein $debug $linein $help $first_run $line_nbr $output $year $filter $filter_fw $filter_acl $filter_interface $filter_exp
	    $filter_src_ip $filter_dst_ip $filter_ip $filter_port $filter_proto $filter_proto $filter_date $filter_time $fileout);
my $prog_date    	= "28 Oct 2015";
my $prog_version        = "3.1.14";

my $start_run = time(); # We want to know how much time it took for the script to run (just for fun)

GetOptions(
        "file=s"		=> \$filein,
	"fileout=s"		=> \$fileout,
        "output=s"      	=> \$output,
        "yearstart=s"   	=> \$year,
        "debug=s"       	=> \$debug,
	"filter"		=> \$filter,
	"filter_exp=s"		=> \$filter_exp,
	"filter_fw=s"		=> \$filter_fw,
	"filter_acl=s"		=> \$filter_acl,
	"filter_interface=s"	=> \$filter_interface,
	"filter_src_ip=s"	=> \$filter_src_ip,
	"filter_dst_ip=s"	=> \$filter_dst_ip,
	"filter_ip=s"		=> \$filter_ip,
	"filter_port=s"		=> \$filter_port,
	"filter_proto=s"	=> \$filter_proto,
	"filter_date=s"		=> \$filter_date,
	"filter_time=s"		=> \$filter_time,
        "help"        		=> \$help,
          );


# Sanity check
if ( not(defined($filein)) or ((not(defined($output)))) or defined($help)){
    print_usage();
    exit;
}
if (not(defined($debug))){
    $debug  = 0;
}


# Beginning of the program.
print "INFO\nINFO   ----> Welcome to the syslog_to_tss conversion script version $prog_version.\n",
    "INFO   ---->\n";

if ($debug eq "255") {
    print "DEBUG  ----> Debugging level is set to level $debug.\n";
    print "DEBUG  ----> main()\t\t: File Name = ", $filein,"\n";
};

## Variables initialisations.
my $syslog_rfc_5424 = 0;
my $first_run = 1;
my $line_nbr = 1;
my $linein = "";
my $lineout = "";
my $OFileName = "";
my $proto = "";
my $proto_word ="";
my $format = "";
my $linecount = 0;
my $printcount = 0;
my $first_log_month = "";
my $localcount = 0;
my %bit_to_netmask = (
    0   => "0.0.0.0",
    1   => "128.0.0.0",
    2   => "192.0.0.0",
    3   => "224.0.0.0",
    4   => "240.0.0.0",
    5   => "248.0.0.0",
    6   => "252.0.0.0",
    7   => "254.0.0.0",
    8   => "255.0.0.0",
    9   => "255.128.0.0",
    10  => "255.192.0.0",
    11  => "255.224.0.0",
    12  => "255.240.0.0",
    13  => "255.248.0.0",
    14  => "255.252.0.0",
    15  => "255.254.0.0",
    16  => "255.255.0.0",
    17  => "255.255.128.0",
    18  => "255.255.192.0",
    19  => "255.255.224.0",
    20  => "255.255.240.0",
    21  => "255.255.248.0",
    22  => "255.255.252.0",
    23  => "255.255.254.0",
    24  => "255.255.255.0",
    25  => "255.255.255.128",
    26  => "255.255.255.192",
    27  => "255.255.255.224",
    28  => "255.255.255.240",
    29  => "255.255.255.248",
    30  => "255.255.255.252",
    31  => "255.255.255.254",
    32  => "255.255.255.255",
);
my %netmask_to_bitmask=reverse %bit_to_netmask;
my %ipname_to_proto = (
    'icmp'	=> '1',
    'igmp'	=> '2',
    'ipv4'	=> '4',
    'ST'	=> '5',
    'tcp'	=> '6',
    'udp'	=> '17',
    'ipv6'	=> '41',
    'rsvp'	=> '46',
    'esp'	=> '50',
    'ah'	=> '51',
    'ospf'	=> '89',
    );
my %ipproto_to_name = reverse %ipname_to_proto;

my %month_nbr = (
	'Jan' => '01',
	'Feb' => '02',
	'Mar' => '03',
	'Apr' => '04',
	'May' => '05',
	'Jun' => '06',
	'Jul' => '07',
	'Aug' => '08',
	'Sep' => '09',
	'Oct' => '10',
	'Nov' => '11',
	'Dec' => '12',
    );
my %month_name = reverse %month_nbr;
my $filter_day;
my $filter_month;
my $filter_year;
my $filter_mask = 0;
my @a_filter_exp_time;
my @a_filter_dst_ip;
my @a_filter_src_ip;

my $filter_ip_is_subnet;
my $filter_dst_ip_is_subnet;
my $filter_src_ip_is_subnet;
my $filter_ip_bitmask = "";
my $filter_src_ip_bitmask = "";
my $filter_dst_ip_bitmask = "";
my $filter_time_type;
my $filter_time_hours;
my $filter_time_minutes;
my $filter_time_seconds;


#  Finalising script call parameters and initialising filter data
if ($filter){
    get_filter_type();
}
&validate_filter_data;


# Testing output file format.

if ($output =~ m/apg/i){
    $output = "APG";
    $OFileName   = $filein . ".apg";
}
elsif ($output =~ m/tss/i){
    $output = "TSS";
    $OFileName   =  $filein . ".tss";
}
else{
    print "ERROR ----> Invalid parameters set in your command line for the output format, you entered : $output.\n";
    print "INFO   ----> Please refer to the usage below.\n";
    print_usage();
    exit;
}

if (defined($fileout)){
    print "DEBUG  ----> Using defined filename $fileout.\n" if ($debug eq "3");
    $OFileName = $fileout;
}

print "INFO   ----> The script will generate a $output file output format.\n",
    "INFO   ----> The output filename will be $OFileName \n";

if ( not(defined($year))){
    my($sec,$min,$hour,$mday,$mon,$yearlocal,$wday,$yday,$isdst) = localtime(time);
    $year = 1900 + $yearlocal;
    print "INFO   ----> The logfile year definition was not specified. defaulting to current year $year for syslog files not containing year information.\n";
}

# Input File Opening
print "INFO   ----> Opening files.";
open SOURCEFILE, "< $filein" or die "\nERROR ----> Cannot open source file";
open OUTFILE, "> $OFileName" or die '\nERROR ----> Cannot open destination file';
print ".... Done!\n",
    "INFO   ----> Source file $filein and destination file $OFileName were opened successfully.\n";
print "INFO   ----> Counting number of entries in file.";
$linecount++ while (<SOURCEFILE>);
print ".... Done.\n";
print "INFO\nINFO   ----> $linecount entries will be processed.\n";
close SOURCEFILE;

open SOURCEFILE, "< $filein" or die "ERROR ----> Cannot reopen source file";

#########################################################################
# Main loop for data handling
#

while (<SOURCEFILE>) {
    #    while (($_ eq "") or ($_ !~ m/^((\w{3}.+)|(\d{4}-))./)){
    while ($_ eq ""){
	next;
    }
    chomp;
    $linein = $_;
    if ($linein !~ m/^((\w{3}.+)|(\d{4}.+))/){
	next;
	chomp;
        $linein = $_;
    }
    $linein =~ tr/ //s;
    $linein =~ s/ ://s;

    if($linein =~ m/^(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2})\+\d{2}:\d{2}.+/){
	    $syslog_rfc_5424 = 1;
    }
    if ($format eq "" and $first_run eq 1){
        print "INFO\nINFO   ----> Detecting File format";
        if ($linein =~ m/^(\w{3})/) {
            $first_log_month = $month_nbr { $1 };
        };
        #Attempting to detect file format
        if ($linein =~ m/id=F.+\s/){
            # This is a FGT device
            $format = "FGT";
        }
        if ($linein =~ m/FWSM|PIX|ASA/){
            # Format is FWSM
            $format = "CISCO";
        }
        if ($linein =~m/swbeta/){
            # Format is safe@office
            $format = "safeoffice";
        }
        if ($linein =~m/fw=/){
            # Format is sonicwall
            $format = "sonicwall";
        }
        if ($linein =~m/NetScreen/){
            # Format is Netscreen
            $format = "NetScreen";
        }
	if ($linein =~m/RT_FLOW/){
            # Format is Netscreen
            $format = "SRX";
        }
        if ($debug eq "255"){
            print "DEBUG  ----> The file type is $format.\n";
        }
        $first_run = 0;
        if ($format eq ""){
            print "\nERROR ----> Impossible to determine log file format." ,
		"\tThe format we are expecting is standard syslog such as : \n" ,
		"\t----> Dec 11 04:28:05 <hostname> <log-event>\n",
		"\t----> 2013-01-16T06:05:57+01:00 <hostname : <log-event>\n",
		"Please ensure the input file format is either Cisco, SonicWall, SafeOffice, Juniper Netscreen or Fortinet and is following syslog RFC. \n";
	    die "Good Bye !\n";
        }
        print ".... done!\n";
        print "INFO   ----> This is a $format logfile.\nINFO\n";
        print "INFO   ----> Beginning analysis.\n";
    }
    if (not($format eq "CISCO") and $output eq "TSS"){
        print "ERROR ----> main() \t\t: This tool only support Cisco for TSS format at the present time.\n";
        exit;
    }
    if ($format eq "FGT"){
        if ($linein =~ m/^.+(status=accept).*/){
            #if ($linein =~ m/^(\w{3})\s+(\d{1,2})\s(\d{2}:\d{2}:\d{2})\s(.+)\sdate.+(src=((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?))).+(src_port=(\d?\d?\d?\d)).+(dst=((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?))).+(dst_port=(\d?\d?\d?\d)).+(proto=(\d?\d?\d))/) {
            if ($linein =~ m/.+(src=((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?))).+(src_port=(\d?\d?\d?\d)).+(dst=((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?))).+(dst_port=(\d?\d?\d?\d)).+(proto=(\d?\d?\d))/) {
                my $month= 0;
                my $day = 0;
                my $time= 0;
                my $hostname = 0;
                my $src_ip = $2;
                my $src_port = $8;
                my $dst_ip = $10;
                my $dst_port = $16;
                my $proto = $18;
                my $icmp_type = 0;
                my $icmp_code = 0;
                my $action = "accept";
		my $aclname = "";
		my $interface = "";
                print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
                #Output format Source Destination Port Protocol Action Date Time
                if($debug eq "255"){
                    print "DEBUG  ----> main()\t\t: $linein \n";
                    print "DEBUG  ----> main()\t\t: 1:$1 2:$2 3:$3 4:$4 5:$5 6:$6 7:$7 8:$8 9:$9 10:$10 11:$11 12:$12 13:$13 14:$14 15:$15 16:$16 17:$17 18:$18 19:$19\n";
                    print "DEBUG  ----> main()\t\t: $format Source IP/port is : $src_ip / $src_port destination IP/port is $dst_ip / $dst_port and protocol is $proto\n";
                }
            }
        }
    }
    if ($format eq "CISCO"){
	#
	# Adding RFC5424 syslog format for future consideration
	#2013-01-16T06:05:57+01:00 COU-IPT1-FW1 : %ASA-6-302013: Built inbound TCP connection 1319494239 for outside:10.198.5.115/50658 (10.198.5.115/50658) to inside:10.206.0.132/2000 (10.206.0.132/2000)
	#Line above will be changed to
	#2013-01-16T06:05:57+01:00 COU-IPT1-FW1 %ASA-6-302013: Built inbound TCP connection 1319494239 for outside:10.198.5.115/50658 (10.198.5.115/50658) to inside:10.206.0.132/2000 (10.206.0.132/2000)
	#
	# RFC3164 syslog format
	#Dec 11 04:28:05 sfmucepnp3.muc %ASA-4-106023: Deny tcp src outside:172.17.8.71/3792 dst inside:173.194.41.98/80 by access-group "outside-in" [0x0, 0x0]
	#Dec 11 08:53:18 sfmucepnp3.muc %ASA-6-302013: Built inbound TCP connection 211050622 for outside2:172.17.244.133/39157 (172.17.244.133/39157) to inside:10.50.161.138/443 (10.50.161.138/443)
	#Dec 11 08:53:18 sfmucepnp3.muc %ASA-6-302013: Built outbound TCP connection 211050621 for outside:10.22.103.22/25 (10.22.103.22/25) to inside:10.50.100.25/36539 (10.50.100.25/36539)
	#Dec 11 08:53:18 sfmucepnp3.muc %ASA-6-302013: Built outbound TCP connection 211050620 for outside:10.172.113.240/80 (10.172.113.240/80) to inside:10.222.11.137/2643 (10.50.192.158/37217)
	#Dec 11 08:53:19 sfmucepnp3.muc %ASA-6-302015: Built inbound UDP connection 211050627 for outside:10.140.137.14/52302 (10.140.137.14/52302) to inside:10.50.250.2/53 (10.50.250.2/53)
	#Dec 15 01:36:40 10.80.101.20 : %ASA-6-106100: access-list gw-pci-prod permitted udp gw-pci-prod/10.80.9.75(61180) -> inside/10.1.1.142(53) hit-cnt 1 300-second interval [0x2fa0dec4, 0x8bf258ad]
	my @listparam = split (/ /,$linein); # Easier way to separate parameters and increase the processing speed.
	my $nb_args = @listparam;
	if ($debug eq"255"){
	    print "DEBUG  ----> main() \t\t: Line a from the file : ";
	    print "$linein\n";
	    my $i=0;
	    print "DEBUG  ----> main() \t\t: Arguments of the line : \n";
	    foreach (@listparam){
		print "DEBUG  ----> main() \t\t:\t$i:$_ \n";
		$i++;
	    }
	}
	my $month   = $listparam[0];
	my ($day, $time, $hostname, $logtype);
	if ($syslog_rfc_5424){
	    #This is a RFC 5424 Syslog.. need to affect variables properly
	    $day = $year = $time = $month;
	    $month =~ s/^\d{4}-(\d{2})-.+/$1/;
	    $day =~ s/^\d{4}-\d{2}-(\d{2})T.+/$1/;
	    $year =~ s/^(\d{4}).+/$1/;
	    $time =~ s/^.+T(.+)\+.+/$1/;
	    $logtype = $listparam[2];
	    $hostname = $listparam[1];
	}
	else{
	    # This is a regular syslog file from RFC 3424 use the old variable definitions
	    $day     = $listparam[1];
	    $time    = $listparam[2];
	    $hostname = $listparam[3];
	    $logtype = $listparam[4];
	}

	if (defined($logtype)){
	    $logtype =~ s/.+(\d{6})./$1/;
	    if ($logtype !~ m/\d{6}/){
		$logtype = $linein;
		$logtype =~ s/.+(30201\d|1060\d\d|106100).+/$1/;
	    }
	}
	else{
	    print "ERROR ----> Log entry for line $linein is invalid, please verify your logfile. Good Bye!\n";
	    exit;
	}


	if ($debug eq "255"){
	    print "DEBUG  ----> main()\t\t: Cisco logtype is\t: $logtype\n";
	}
	my ($contype,$action,$icmp_type ,$icmp_code ,$src_ip ,$src_port)="";
	my ($dst_port ,$dst_ip ,$isnat,$nat_for_ip,$nat_for_port) = "";
	my ($nat_to_ip ,$nat_to_port, $interface, $aclname) = "";

	if ($logtype =~ m/(302013|302015)/){
	    #Dec 11 08:53:18 sfmucepnp3.muc %ASA-6-302013: Built inbound TCP connection 211050622 for outside2:172.17.244.133/39157 (172.17.244.133/39157) to inside:160.50.161.138/443 (160.50.161.138/443)
	    #Dec 11 08:53:18 sfmucepnp3.muc %ASA-6-302013: Built outbound TCP connection 211050620 for outside:194.172.113.240/80 (194.172.113.240/80) to inside:10.222.11.137/2643 (160.50.192.158/37217)
	    #2013-01-16T06:05:57+01:00 COU-IPT1-FW1 %ASA-6-302013: Built inbound TCP connection 1319494239 for outside:10.198.5.115/50658 (10.198.5.115/50658) to inside:10.206.0.132/2000 (10.206.0.132/2000)
	    my $linedata = $linein;
	    $linedata =~ s/.+(302013|302015):(.+)/$2/;
	    my @l_listparam = split (" ",$linedata);

	    if ($1 eq 302013){
                $proto = 6;
            }
            else{
                $proto = 17;
            }
	    $contype = $l_listparam[1];
	    $src_ip = $src_port = $l_listparam[6];
	    $nat_for_ip = $nat_for_port = $l_listparam [7];
	    $dst_ip = $dst_port = $l_listparam [9];
	    $nat_to_ip = $nat_to_port = $l_listparam [10];
	    $interface = $l_listparam[6];
	    $icmp_type = 0;
	    $icmp_code = 0;
	    $action = "accept";
	    $isnat = 0;
	    $contype =~ s/(outbound|inbound)/lc($1)/ige;
	    $src_ip =~ s/.+:((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
	    $src_port =~ s/.+\/(\d{1,5})$/$1/;
	    $nat_for_ip =~ s/.((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
	    $nat_for_port =~ s/.+\/(\d{1,5}).$/$1/;
	    $dst_ip =~ s/.+:((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
	    $dst_port =~ s/.+\/(\d{1,5})$/$1/;
	    $nat_to_ip =~ s/.((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
	    $nat_to_port =~ s/.+\/(\d{1,5})$/$1/;
	    $interface =~ s/^(.+):.+/$1/;
	    $aclname = "";
	    if($debug eq "255"){
		print "DEBUG  ----> main()\t\t: Printing Current line \t : $linein \n";
		my $i=0;
		print "DEBUG  ----> main()\t\t: List of arguments retrieved from the line:\n";
		foreach (@listparam){
		    print "DEBUG  ----> main()\t\t:\t$i:$_ \n";
		    $i++;
		}
		print "DEBUG  ----> main()\t\t: $format Source IP/port is : $src_ip / $src_port destination IP/port is $dst_ip / $dst_port and protocol is $proto\n";
	    }
	    if ($contype eq "outbound"){
		if (($nat_for_ip ne $dst_ip) or ($nat_for_port ne $dst_port)){
		    # We have NAT and this is an outbound connection that needs to be reversed.
		    $isnat = 1;
		    $dst_ip = $nat_to_ip;
		    $dst_port = $nat_for_port;
		    $src_ip = $nat_for_ip;
		    $src_port = $nat_to_port;
		    #$interface = $listparam[14];
		    #$interface =~ s/^(.+):.+/$1/;
		}
		print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
	    }
	    else{
		print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
	    }
	}
        elsif ($logtype =~ m/(106001|106006)/){
	    #Dec 11 04:28:04 sfmucepnp3.muc %ASA-2-106006: Deny inbound UDP from 160.50.192.158/19117 to 172.17.16.16/161 on interface outside
	    #Dec 11 04:28:04 sfmucepnp3.muc %ASA-2-106001: Inbound TCP connection denied from 160.49.139.146/50241 to 172.17.15.110/7777 flags SYN  on interface outside
            $nat_for_ip = "";
	    $nat_for_port = "";
            $action = "drop";
	    $icmp_type = 0;
	    $icmp_code = 0;
	    my $linedata = $linein;
	    $aclname = "";
	    $linedata =~ s/.+(106001|106006):(.+)/$2/;
	    my @l_listparam = split (" ",$linedata);

	    if ($1 eq 106001){
                $proto = 6;
		$src_ip = $src_port = $l_listparam[5];
		$dst_ip = $dst_port = $l_listparam [7];
		$interface = $l_listparam[12];
		$src_ip =~ s/((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
		$src_port =~ s/.+\/(\d{1,5})$/$1/;
		$dst_ip =~ s/((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
		$dst_port =~ s/.+\/(\d{1,5})$/$1/;
	    }
            else{
                $proto = 17;
		$src_ip = $src_port = $l_listparam[4];
		$dst_ip = $dst_port = $l_listparam [6];
		$interface = $l_listparam[9];
		$src_ip =~ s/((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
		$src_port =~ s/.+\/(\d{1,5})$/$1/;
		$dst_ip =~ s/((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
		$dst_port =~ s/.+\/(\d{1,5})$/$1/;
	    }
	    if($debug eq "255"){
		print "DEBUG  ----> main() \t\t: $linein \n";
		my $i=0;
		foreach (@l_listparam){
		    print "DEBUG  ----> main() \t\t:\t$i:$_ \n";
		    $i++;
		}
		print "DEBUG  ----> main() \t\t: Calling print_logdata() with parameters :\n",
		    "\t\t\t\tYear:$year \tMonth:$month \tDay:$day \tTime:$time \tHostname:$hostname \tSRC_IP:$src_ip \tDST_IP:$dst_ip \tDST_PORT:$dst_port \tPROTO:$proto\n",
		    "\t\t\t\tICMP_Type:$icmp_type \tICMP_Code:$icmp_code \tAction:$action \t INTERFACE:$interface \tACL:$aclname\n";
	    }
	    print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
        }
	elsif ($logtype =~ m/(106100)/){
	    #Dec 15 01:36:40 10.80.101.20 : %ASA-6-106100: access-list gw-pci-prod permitted udp gw-pci-prod/10.80.9.75(61180) -> inside/10.1.1.142(53) hit-cnt 1 300-second interval [0x2fa0dec4, 0x8bf258ad]
	    #Dec 4 20:25:21 10.85.254.10 %ASA-6-106100: access-list pscdmz denied tcp pscdmz/155.16.61.33(3181) -> inside/165.136.132.33(44252) hit-cnt 1 first hit [0xb771090f, 0x0]
            $nat_for_ip = "";
	    $nat_for_port = "";
	    $icmp_type = 0;
	    $icmp_code = 0;

	    my $linedata = $linein;
	    $linedata =~ s/.+(106100):(.+)/$2/;
	    my @l_listparam = split (" ",$linedata);

	    $proto = $ipname_to_proto { $l_listparam[3] };
	    $src_ip = $src_port = $l_listparam[4];
	    $dst_ip = $dst_port = $l_listparam [6];
	    $interface = $l_listparam[4];
	    $aclname = $l_listparam[1];

	    if ($l_listparam[2] eq "permitted"){
		$action = "accept";
	    }
	    else{
		$action = "drop";
	    }


	    $src_ip =~ s/.+\/((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
	    $src_port =~ s/.+\((\d{1,5}).+$/$1/;
	    $dst_ip =~ s/.+\/((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
	    $dst_port =~ s/.+\((\d{1,5}).+$/$1/;
	    $interface =~ s/^(.+)\/.+/$1/;
	    if($debug eq "255"){
		print "DEBUG  ----> main()\t\t: $linein \n",
		    "DEBUG  ----> main()\t\t: Arguments data for log $logtype.\n";
		my $i=0;
		foreach (@l_listparam){
		    print "DEBUG  ----> main()\t\t:\t$i:$_ \n";
		    $i++;
		}

		print "DEBUG  ----> main()\t\t: $format Source IP/port is : $src_ip / $src_port destination IP/port is $dst_ip / $dst_port and protocol is $proto\n";
	    }
	    print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
	}
        elsif ($logtype =~ m/106014/){
            $proto = 1;
	    #Dec 11 06:00:08 sfmucepnp3.muc %ASA-3-106014: Deny inbound icmp src outside:160.50.13.31 dst outside:172.17.0.205 (type 8, code 0)
	    my $linedata = $linein;
	    $linedata =~ s/.+(106014):(.+)/$2/;
	    my @l_listparam = split (" ",$linedata);
	    $src_ip = $l_listparam[4];
	    $dst_ip = $l_listparam[6];
	    $interface = $l_listparam[4];
	    $icmp_type = $l_listparam[8];
	    $icmp_code = $l_listparam[10];
	    $src_ip =~ s/.+:((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
	    $dst_ip =~ s/.+:((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
	    $src_port = $dst_port = $isnat = 0;
	    $action  = "drop";
	    $icmp_type =~ s/([0-9]+).+/$1/;
            $icmp_code =~ s/([0-0]+).+/$1/;
	    $interface =~ s/^(.+):.+/$1/;
	    $aclname = "";
	    if($debug eq "255"){
		print "DEBUG  ----> main()\t\t: $linein \n";
		my $i=0;
		foreach (@l_listparam){
		    print "DEBUG  ----> main()\t\t:\t $i:$_ \n";
		    $i++;
		}
		print "DEBUG  ----> main()\t\t: $format Source IP/port is : $src_ip / $src_port destination IP/port is $dst_ip / $dst_port and protocol is $proto\n";
	    }
	    print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
        }
        elsif ($logtype =~ m/106023/){
            # This will be automatically generated by rules that are not logged.
	    #Dec 11 04:28:06 sfmucepnp3.muc %ASA-4-106023: Deny tcp src outside:172.17.8.71/3794 dst inside:173.194.41.110/80 by access-group "outside-in" [0x0, 0x0]
            #Dec 11 04:28:05 sfmucepnp3.muc %ASA-4-106023: Deny tcp src outside:172.17.8.71/3791 dst inside:173.194.41.105/80 by access-group "outside-in" [0x0, 0x0]
	    my $linedata = $linein;
	    $linedata =~ s/.+(106023):(.+)/$2/;
	    my @l_listparam = split (" ",$linedata);

	    $proto = $ipname_to_proto { $l_listparam[1] };
	    $src_ip = $src_port = $l_listparam[3];
	    $dst_ip = $dst_port = $l_listparam[5];
	    $interface = $l_listparam[3];
	    $icmp_type = 0;
	    $icmp_code = 0;
	    $aclname   = $l_listparam[9];
	    $aclname   =~ s/\"//g;
	    $src_ip =~ s/.+:((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
	    $src_port =~ s/.+\/(\d{1,5})$/$1/;
	    $dst_ip =~ s/.+:((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})).+/$1/;
	    $dst_port =~ s/.+\/(\d{1,5})$/$1/;
	    $action  = "drop";
	    $icmp_type =~ s/\[0x([0-9]+)./$1/;
	    $icmp_code =~ s/0x([0-9]+).+/$1/;
	    $interface =~ s/^(.+):.+/$1/;
	    if($debug eq "255"){
		print "DEBUG  ----> main()\t\t: $linein \n";
		my $i=0;
		foreach (@listparam){
		    print "DEBUG  ----> main()\t\t:\t $i:$_\n";
		    $i++;
		}
		print "DEBUG  ----> main()\t\t: $format Source IP/port is : $src_ip / $src_port destination IP/port is $dst_ip / $dst_port and protocol is $proto\n";
	    }
	    print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
        }
	else{
	    if ($debug eq "255"){
		print "DEBUG  ----> main() \t\t: Line format $logtype is not interesting for our script hence is not being processed.\n";
	    }
	}
    }
    if ($format eq "safeoffice"){
        #if (($linein =~ m/^.+(Inbound).*/) || ($linein =~ m/^.+(Outbound).*/)) { # Removed for Optimisation.
        if (($linein =~ m/^.+(Inbound|Outbound).*/)) {
            if ($linein =~ m/.+(Src:((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?))).+(SPort:(\d?\d?\d?\d)).+(Dst:((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?))).+(DPort:(\d?\d?\d?\d)).+(IPP:(\d?\d?\d))/) {
                my $src_ip = $2;
                my $src_port = $8;
                my $dst_ip = $10;
                my $dst_port = $16;
                $proto = $18;
		my $month = "";
		my $day = "";
		my $time = "";
		my $hostname = "";
		my $icmp_type = 0;
		my $icmp_code = 0;
		my $action = "accept";
		my $interface = "";
		my $aclname = "";
		print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
                #print OUTFILE $src_ip . " " . $dst_ip . " " . $dst_port . " " . $proto . "\n";
                if ($debug eq "255"){
                    print "Format safe: $format Source IP/port is : $src_ip / $src_port destination IP/port is $dst_ip / $dst_port and protocol is $proto\n";
                }
            }
        }
    }
    if ($format eq "NetScreen"){
	#Feb 17 00:01:46 192.168.1.166 Juniper-Rome: NetScreen device_id=Juniper-Rome  [Root]system-notification-00257(traffic): start_time="2011-02-17 00:40:25" duration=4 policy_id=16 service=tcp/port:49 proto=6 src zone=Untrust dst zone=Trust action=Permit sent=403 rcvd=267 src=172.16.2.100 dst=192.168.55.134 src_port=28882 dst_port=49 src-xlated ip=172.16.2.100 port=28882
        if ($linein =~m/^.+(00257),*/){
            if ($linein =~ m/^.+(action=Permit).*/){
                if ($linein =~ m/icmp/){
                    if ($linein =~ m/.+(proto=(\d\d?\d?)).+(src=((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?))).+(dst=((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?))).+(type=(\d?\d?\d)).*/) {
                        my $src_ip = $4;
                        my $src_port = 0;
                        my $dst_ip = $10;
                        my $dst_port = $16;
                        my $proto = $2;
			my $month = "";
			my $day = "";
			my $time = "";
			my $hostname = "";
			my $icmp_type = 0;
			my $icmp_code = 0;
			my $action = "accept";
			my $interface = "";
			my $aclname = "";
                        #print OUTFILE $src_ip . " " . $dst_ip . " " . $dst_port . " " . $proto . "\n";
			print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
                        if ($debug eq "255"){
                            print "Format NetScreen: $format Source IP/port is : $src_ip / $src_port destination IP/port is $dst_ip / $dst_port and protocol is $proto\n";
                        }
                    }
                }
                else
                {
                    if ($linein =~ m/.+(proto=(\d?\d?\d)).+(src=((\d\d?\d)?\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?))).+(dst=((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?))).+(src_port=(\d?\d?\d?\d)).+(dst_port=(\d?\d?\d?\d)).+/) {
                        my $src_ip = $4;
                        my $src_port = $16;
                        my $dst_ip = $10;
                        my $dst_port = $18;
                        my $proto = $2;
			my $month = "";
			my $day = "";
			my $time = "";
			my $hostname = "";
			my $icmp_type = 0;
			my $icmp_code = 0;
			my $action = "accept";
                        #print OUTFILE $src_ip . " " . $dst_ip . " " . $dst_port . " " . $proto . "\n";
			my $interface = "";
			my $aclname = "";
			print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
                        if ($debug eq "255"){
                            print "Format Netscreen: $format Source IP/port is : $src_ip / $src_port destination IP/port is $dst_ip / $dst_port and protocol is $proto\n";
                        }
                    }
                }
            }
        }
    }
    if ($format eq "SRX"){
	#Feb  2 09:06:55 74.217.12.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.94.37.83/5->10.74.237.138/56928 icmp 10.94.37.83/5->10.74.237.138/56928 None None 1 3 trust trust 40044 N/A(N/A) reth1.0
	#UDP NAT
	#Feb  2 09:06:54 74.217.12.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.74.237.229/27194->10.217.12.208/80 junos-http 10.74.237.229/27194->10.14.1.12/80 None static_nat97 6 31 UCS dmz 19899 N/A(N/A) reth4.0 (NAT)
        #TCP
        #Feb  2 09:06:54 74.217.12.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.125.183.19/54220->10.74.237.2/53 junos-dns-udp 10.125.183.19/54220->10.74.237.2/53 None None 17 489_1 untrust trust 33234 N/A(N/A) reth0.0
	#Feb  2 09:06:54 74.217.12.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.74.237.229/60583->10.217.12.208/80 junos-http 10.74.237.229/60583->10.14.1.12/80 None static_nat97 6 31 UCS dmz 48969 N/A(N/A) reth4.0
	#Sep 17 08:00:05 THSRAHNUNFW01P RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.9.0.117/52689->10.9.0.136/5985 None 10.9.0.117/52689->10.9.0.136/5985 None None 6 249 RAH_ADM_FORET RAH_INFRA_SVC 44334 N/A(N/A) reth1.806

	my ($contype,$action,$icmp_type ,$icmp_code ,$src_ip ,$src_port)="";
	my ($dst_port ,$dst_ip ,$isnat,$nat_for_ip,$nat_for_port) = "";
	my ($nat_to_ip ,$nat_to_port, $interface, $aclname,$hostname) = "";
	my ($day,$month,$time,$proto)="";

        if ($linein =~m/^.+(RT_FLOW_SESSION_CREATE),*/){
	    my @l_listparam = split (" ",$linein);

	    my $i=0;
	    if ($debug eq "255"){
		foreach (@l_listparam){
		    print "DEBUG  ----> main()\t\t:\t $i:$_\n";
		    $i++;
		}
	    }
	    $month = $l_listparam[0];
	    $day   = $l_listparam[1];
	    $time  = $l_listparam[2];
	    $hostname = $l_listparam[3];
	    $icmp_type = $l_listparam[13];
	    $icmp_code = 0;
	    $action = "accept";
	    $interface = $l_listparam[19];
	    $aclname = $l_listparam[14];

	    my $flow = $l_listparam[8];
	    my $nat_flow = $l_listparam[10];
	    $proto = $l_listparam[13];
	    $src_ip = $dst_ip = $src_port = $dst_port = $flow;

	    $src_ip   =~ s/^((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))\/(\d{1,5})->((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))\/(\d{1,5}).*/$1/;
	    $src_port =~ s/^((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))\/(\d{1,5})->((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))\/(\d{1,5}).*/$6/;
	    $dst_ip   =~ s/^((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))\/(\d{1,5})->((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))\/(\d{1,5}).*/$7/;
	    $dst_port =~ s/^((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))\/(\d{1,5})->((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))\/(\d{1,5}).*/$12/;

	    print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
	    if ($debug eq "255"){
		print "Format SRX: $format Source IP/port is : $src_ip / $src_port destination IP/port is $dst_ip / $dst_port and protocol is $proto\n";
	    }
        }
    }
    if ($format eq "sonicwall"){
        if ($linein =~ m/^.+(Opened|ICMP).*/){
            if ($linein =~ m/.+(src=((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?):(\d\d?\d?\d?\d?)).+(dst=((\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?):(\d\d?\d?\d?\d?)))).*/) {
                my $src_ip = "$3.$4.$5.$6";
                my $src_port = $7;
                my $dst_ip = "$10.$11.$12.$13";
                my $dst_port = $14;
                if ($linein =~ m/.+(proto=(\w\w?\w?\w?)).*/){
                    $proto_word = $2;
                    if ($proto_word eq "udp"){
                        $proto = "17";
                    }
                    elsif ($proto_word eq "tcp"){
                        $proto = "6";
                    }
                    else {
                        $proto = 1;
                    }
		    my $month = "";
		    my $day = "";
		    my $time = "";
		    my $hostname = "";
		    my $icmp_type = 0;
		    my $icmp_code = 0;
		    my $action = "accept";
		    my $interface = "";
		    my $aclname = "";
		    print_logdata ($year,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
                    #print OUTFILE $src_ip . " " . $dst_ip . " " . $dst_port . " " . $proto . "\n";
                    if ($debug eq "255"){
                       print "Format safe: $format Source IP/port is : $src_ip / $src_port destination IP/port is $dst_ip / $dst_port and protocol is $proto\n";
                    }
                }
            }
        }
    }
    $proto = "";
    $proto_word = "";
    $linein = "";
    $line_nbr ++;
    $localcount ++;
    # Printing progress Bar :-)
    if ($localcount eq 512 ){
    print progress_bar($line_nbr, $linecount, 25, '=' );
    $localcount = 0;
    }
    elsif ($linecount eq $line_nbr){
	print progress_bar($line_nbr, $linecount, 25, '=' );
    }
}

my $end_run = time();
my $run_time = $end_run - $start_run;

print "\nINFO\nINFO\n",
    "INFO   ----> The TSS requested output file is : $OFileName.\n",
    "INFO   ----> $printcount log ";
if ($printcount eq 1){
    print "entry was written to the output file.\n",
	"INFO   ----> Program terminated successfully in : $run_time seconds.\n",
	"\n\n",
	"Good Bye !\n";
}
else{
    print " entries were written to the output file.\n",
	"INFO   ----> Program terminated successfully in : $run_time seconds.\n",
	"\n\n",
	"Good Bye !\n";
}

################### Sub Procedures are starting below this line #######################

sub get_filter{
    # This sub is for getting the filters that should be applied to the syslog file
    # Input is nothing
    # Output is mulitple array for @filter_date, @filter_ip, @filter_
}

sub apply_filter{
    # This sub is for applying filter to the syslog file before sending the data to the output file
    # Parameters are $month, $day, $time, $hostname, $src_ip, $src_port, $dst_ip, $dst_port, $proto, $icmp_type, $icmp_code, $action,$interface,$aclname
    #
    # Filter Bitmask are :
    #  - ACL-Name	= 0x0200  = 512
    #  - Interface	= 0x0100  = 256
    #  - hostname 	= 0x0080  = 128
    #  - Date		= 0x0040  =  64
    #  - Time 		= 0x0020  =  32
    #  - IP		= 0x0010  =  16
    #  - SRC_IP		= 0x0008  =   8
    #  - DST_IP		= 0x0004  =   4
    #  - Protocol	= 0x0002  =   2
    #  - Port 		= 0x0001  =   1
    #
    #

    my ($lf_year,$lf_month,$lf_day,$lf_time,$lf_hostname,$lf_src_ip,$lf_src_port,$lf_dst_ip,$lf_dst_port,$lf_proto,$lf_icmp_type,$lf_icmp_code,$lf_action,$lf_interface,$lf_aclname) = @_;
    my $l_hostname_result = 0;
    my $l_date_result = 0;
    my $l_time_result = 0;
    my $l_dst_ip_result = 0;
    my $l_src_ip_result = 0;
    my $l_ip_result = 0;
    my $l_proto_result = 0;
    my $l_port_result = 0;
    my $l_interface_result = 0;
    my $l_acl_result = 0;
    my ($l_result, $l_result_mask) = 0;

    if($debug eq "255"){
	print "DEBUG  ----> apply_filter()\t: Procedure called:\n";
	my $i=0;
	print "DEBUG  ----> apply_filter()\t: List of arguments retrieved when the function was called:\n";
	foreach (@_){
	    print "DEBUG  ----> apply_filter()\t:\t $i:$_ \n";
	    $i++;
	}
	print "DEBUG  ----> apply_filter()\t: Current filters are \n",
	    "DEBUG  ----> apply_filter()\t:\t ACL Name \t: $filter_acl\n",
	    "DEBUG  ----> apply_filter()\t:\t Interface \t: $filter_interface\n",
	    "DEBUG  ----> apply_filter()\t:\t Hostname \t: $filter_fw\n",
	    "DEBUG  ----> apply_filter()\t:\t Time   \t: $filter_time\n",
	    "DEBUG  ----> apply_filter()\t:\t IP     \t: $filter_ip\n",
	    "DEBUG  ----> apply_filter()\t:\t SRC_IP \t: $filter_src_ip\n",
	    "DEBUG  ----> apply_filter()\t:\t DST_IP \t: $filter_dst_ip\n",
	    "DEBUG  ----> apply_filter()\t:\t Protocol\t: $filter_proto\n",
	    "DEBUG  ----> apply_filter()\t:\t Port    \t: $filter_port\n",
	    "DEBUG  ----> apply_filter()\t:\t Filter Mask: $filter_mask\n";
    }

    # Bitmask for ACL Name filter  0x0200
    if (($filter_mask & 512) == 512){
	if($lf_aclname =~ m/$filter_acl/i){
	    $l_acl_result = 512;
	    print "DEBUG  ----> apply_filter()\t: ACL Name match printing data\n" if ($debug eq "255");
	}
    }

    # Bitmask for Interface filter 0x0100
    if (($filter_mask & 256) == 256){
	if($lf_interface =~ m/$filter_interface/){
	    $l_interface_result = 256;
	    print "DEBUG  ----> apply_filter()\t: Interface match printing data\n" if ($debug eq "255");
	}
    }

    # Bitmask for Hostname filter 0x80
    if (($filter_mask & 128) == 128){
	if($lf_hostname =~ m/$filter_fw/){
	    $l_hostname_result = 128;
	    print "DEBUG  ----> apply_filter()\t: Hostname match printing data\n" if ($debug eq "255");
	}
    }

    # Bitmask for Day filter 0x40
    if (($filter_mask & 64) == 64){
	if ($syslog_rfc_5424){
	    if(($lf_day eq $filter_day) and ($lf_year eq $filter_year) and ($lf_month eq $filter_month)){
		$l_date_result = 64;
		print "DEBUG  ----> apply_filter()\t: Syslog RFC5424 and match for date.\n" if ($debug eq "255");
	    }
	}
	else{
	    if(($lf_day eq $filter_day) and ($year eq $filter_year) and ($lf_month eq $month_nbr { $filter_month })){
		$l_date_result = 64;
		print "DEBUG  ----> apply_filter()\t: Non-Syslog RFC5424 and match for date.\n" if ($debug eq "255");
	    }
	}
    }
    # Bitmask for Time filter 0x20
    if (($filter_mask & 32) == 32){
	if ($filter_time_type eq "advanced"){
	    print "DEBUG  ----> apply_filter()\t: Match for advanced time selection.\n" if ($debug eq "255");
	    my @laf_time = split (":",$lf_time);
	    if ($laf_time[0] == $filter_time_hours){
		print "DEBUG  ----> apply_filter()\t: We matched the hour.\n" if ($debug eq "255");
		if ($filter_time_minutes eq "*"){
		    $l_time_result = 32;
		    print "DEBUG  ----> apply_filter()\t: We are printing the line any minutes was selected.\n" if ($debug eq "255");
		}
		elsif($laf_time[1] == $filter_time_minutes){
		    $l_time_result = 32;
		    print "DEBUG  ----> apply_filter()\t: We are printing the line specific $filter_time_minutes minutes were selected.\n" if ($debug eq "255");
		}
		elsif($filter_time_seconds eq "*"){
		    $l_time_result = 32;
		    print "DEBUG  ----> apply_filter()\t: We are printing the line any seconds was selected.\n" if ($debug eq "255");
		}
		elsif ($laf_time[2] == $filter_time_seconds){
		    $l_time_result = 32;
		    print "DEBUG  ----> apply_filter()\t: We are printing the line specific seconds $filter_time_seconds seconds were selected.\n" if ($debug eq "255");
		}
		print "DEBUG  ----> apply_filter()\t: We finish the match current result is $l_result.\n" if ($debug eq "255");
	    }
	    else{
		print "DEBUG  ----> apply_filter()\t: No Match for this line.\n" if ($debug eq "255");
	    }
	}
	elsif($filter_time_type eq "simple"){
	    if ($lf_time eq $filter_time){
		$l_time_result = 1;
		print "DEBUG  ----> apply_filter()\t: Match for non-advanced time.\n" if ($debug eq "255");
	    }
	    else{
		print "DEBUG  ----> apply_filter()\t: No match for non-advanced time.\n" if ($debug eq "255");
	    }
	}
	elsif($filter_time_type eq "none"){
	    print "DEBUG  ----> apply_filter()\t: No filtering on time.\n" if ($debug eq "255");
	}
    }

    #  Bitmask for IP filter 0001 0000
    if (($filter_mask & 16) == 16){
	if(($lf_src_ip eq $filter_ip) or ($lf_dst_ip eq $filter_ip)){
	    $l_ip_result = 16;
	}
	elsif ($filter_ip_is_subnet eq 1){
	    my $l_bin_src_ip = unpack('B32', pack('C4C4C4C4', split(/\./, $lf_src_ip)));
	    my $l_bin_dst_ip = unpack('B32', pack('C4C4C4C4', split(/\./, $lf_dst_ip)));
	    my $l_bin_filter_net_mask = unpack('B32', pack('C4C4C4C4', split(/\./, $bit_to_netmask{$filter_ip_bitmask})));
	    my $l_bin_src_net = $l_bin_src_ip & $l_bin_filter_net_mask;
	    my $l_bin_dst_net = $l_bin_dst_ip & $l_bin_filter_net_mask;
	    if ((bin_to_ip($l_bin_src_net) eq $filter_ip) or (bin_to_ip($l_bin_dst_net) eq $filter_ip)){
		$l_ip_result = 16 ;
	    }
	    if ($debug eq "255"){
		print "DEBUG  ----> apply_filter()\t: Filter for IP applied for subnet $filter_ip\n",
			"DEBUG  ----> apply_filter()\t: \t IP SRC Binary  : $lf_src_ip \t $l_bin_src_ip\n",
			"DEBUG  ----> apply_filter()\t: \t Filter Bitmask : $filter_ip_bitmask \t\t $l_bin_filter_net_mask\n",
			"DEBUG  ----> apply_filter()\t: \t SRC_IP Network for $lf_src_ip is :\t" . bin_to_ip($l_bin_src_net) . "\n",
			"DEBUG  ----> apply_filter()\t: \t DST_IP Network for $lf_dst_ip is :\t" . bin_to_ip($l_bin_dst_net) . "\n",
			"DEBUG  ----> apply_filter()\t: \t IP result is   : $l_ip_result\n" ;
	    }
	}
    }
    #  Bitmask for SRC IP filter 0x08
    if (($filter_mask & 8) == 8){
	if($lf_src_ip eq $filter_src_ip){
	    $l_src_ip_result = 8;
	}
	elsif ($filter_src_ip_is_subnet eq 1){
	    my $l_bin_src_ip = unpack('B32', pack('C4C4C4C4', split(/\./, $lf_src_ip)));
	    my $l_bin_filter_net_mask = unpack('B32', pack('C4C4C4C4', split(/\./, $bit_to_netmask{$filter_src_ip_bitmask})));
	    my $l_bin_src_net = $l_bin_src_ip & $l_bin_filter_net_mask;
	    if (bin_to_ip($l_bin_src_net) eq $filter_src_ip){
		$l_src_ip_result = 8 ;
	    }
	    if ($debug eq "255"){
		print "DEBUG  ----> apply_filter()\t: Filter for IP applied for subnet $filter_ip\n",
			"DEBUG  ----> apply_filter()\t: \t IP SRC Binary  : $lf_src_ip \t $l_bin_src_ip\n",
			"DEBUG  ----> apply_filter()\t: \t Filter Bitmask : $filter_src_ip_bitmask \t\t $l_bin_filter_net_mask\n",
			"DEBUG  ----> apply_filter()\t: \t SRC_IP Network for $lf_src_ip is :\t" . bin_to_ip($l_bin_src_net) . "\n",
			"DEBUG  ----> apply_filter()\t: \t IP result is   : $l_src_ip_result\n";
	    }
	}
    }

    # Bitmask for DST IP filter 0x04
    if (($filter_mask & 4) == 4){
	if($lf_dst_ip eq $filter_dst_ip){
	    $l_dst_ip_result = 4;
	}
	elsif ($filter_dst_ip_is_subnet eq 1){
	    my $l_bin_dst_ip = unpack('B32', pack('C4C4C4C4', split(/\./, $lf_dst_ip)));
	    my $l_bin_filter_net_mask = unpack('B32', pack('C4C4C4C4', split(/\./, $bit_to_netmask{$filter_dst_ip_bitmask})));
	    my $l_bin_dst_net = $l_bin_dst_ip & $l_bin_filter_net_mask;
	    if (bin_to_ip($l_bin_dst_net) eq $filter_dst_ip){
		$l_dst_ip_result = 4 ;
	    }
	    if ($debug eq "255"){
		print "DEBUG  ----> apply_filter()\t: Filter for IP applied for subnet $filter_ip\n",
			"DEBUG  ----> apply_filter()\t: \t IP DST Binary  : $lf_dst_ip \t $l_bin_dst_ip\n",
			"DEBUG  ----> apply_filter()\t: \t Filter Bitmask : $filter_dst_ip_bitmask \t\t $l_bin_filter_net_mask\n",
			"DEBUG  ----> apply_filter()\t: \t DST IP Network for $lf_dst_ip is :\t" . bin_to_ip($l_bin_dst_net) . "\n",
			"DEBUG  ----> apply_filter()\t: \t IP result is   : $l_dst_ip_result\n";
	    }
	}
    }

    # Bitmask for Protocol Filter 0x02
    if (($filter_mask & 2) == 2){
	if($lf_proto eq $filter_proto){
	    $l_proto_result = 2;
	}
    }

    # Bitmask for Port Filter 0x01
    if (($filter_mask & 1) == 1){
	if ($lf_dst_port eq $filter_port){
	    $l_port_result = 1;
	}
    }
    if ($debug eq "255"){
	print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_acl_result      = $l_acl_result.\n";
	print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_interface_result= $l_interface_result.\n";
	print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_hostname_result = $l_hostname_result.\n";
	print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_date_resul      = $l_date_result.\n";
	print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_time_result     = $l_time_result.\n";
	print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_ip_result       = $l_ip_result.\n";
	print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_src_ip_result   = $l_src_ip_result.\n";
	print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_dst_ip_result   = $l_dst_ip_result.\n";
	print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_proto_result    = $l_proto_result.\n";
	print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_port_result     = $l_port_result.\n";
    }

    $l_result_mask = $l_acl_result | $l_interface_result | $l_hostname_result | $l_date_result | $l_time_result | $l_ip_result | $l_src_ip_result | $l_dst_ip_result | $l_proto_result | $l_port_result;
    print "DEBUG  ----> apply_filter()\t: Result after applying filter is l_result_mask = $l_result_mask.\n" if ($debug eq "255");
    if ($filter_mask == $l_result_mask){
	$l_result = 1;
    }
    if($debug eq "255"){
	print "DEBUG  ----> apply_filter:\t: Procedure is terminating:\n";
	if ($l_result eq 1){
	    print "DEBUG  ----> apply_filter: \t: Return variable \$l_result $l_result line is to be printed out.\n";
	}
	else{
	    print "DEBUG  ----> apply_filter: \t: Return variable \$l_result $l_result line will not be printed out.\n";
	}
    }
    return $l_result;
}

sub parse_cisco_log{
    # This sub is for parsing log entries from Cisco firewalls in the future
}

sub print_logdata {
    # Generic procedure to print the data comping from the previous procedures
    # Variable Order : print_logdata ($month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action);
    my ($lyear,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname) = @_;
    my $l_filter_result = 0;
    if($debug eq "255"){
	print "DEBUG  ----> print_logdata()\t: Parameters passed to the function\n";
	my $i=0;
	foreach (@_){
	    print "DEBUG  ----> print_logdata()\t:\t$i:$_ \n";
	    $i++;
	}
    }
    if (not defined($interface)){
	$interface = "";
    }

    # In the case of ICMP we are using dst_port for type and src_port for ICMP Code
    if ($debug eq "255"){
        print "DEBUG  ----> print_logdata()\t: $linein \n",
	    "DEBUG  ----> print_logdata()\t: Params year=$year month=$month day:$day time:$time hostname:$hostname src_ip:$src_ip src_port:$src_port dst_IP:$dst_ip dst_port:$dst_port $proto $icmp_type $icmp_code Interface: $interface\n";
    }

    if ($filter == 2){
	if ($debug eq "255"){
	    print "DEBUG  ----> print_logdata()\t: Calling filter with procedure parameters.\n",
	}
	$l_filter_result = apply_filter($lyear,$month,$day,$time,$hostname,$src_ip,$src_port,$dst_ip,$dst_port,$proto,$icmp_type,$icmp_code,$action,$interface,$aclname);
	print "DEBUG  ----> print_logdata()\t: We finish the filtering process current result is $l_filter_result.\n" if ($debug eq "255");
    }

    if (($l_filter_result and $filter == 2) or $filter == 0 ){
	print "DEBUG  ----> print_logdata()\t: Log entry will be printed out.\n" if ($debug eq "255");
	# This value is 1 we print the log entry
	if ($output eq "APG" and $action eq "accept"){
	    print "DEBUG  ----> print_logdata()\t: We are printing an APG logfile.\n" if ($debug eq "255");
	    # Format is APG and Action accept
	    print OUTFILE "$src_ip $dst_ip $dst_port $proto\n";
	    $printcount ++;
	}
	elsif ($output eq "TSS"){
	    print "DEBUG  ----> print_logdata()\t: We are pringing a TSS logfile.\n" if ($debug eq "255");
	    #Format is TSS : 10.0.46.21 10.0.46.255 137 17 drop 15Dec2012 12:12:02 outside
	    #Format is TSS : 10.0.46.21 10.0.46.255 137 17 accept 15Dec2012 12:12:02 outside
	    if ( ($first_log_month gt $month_nbr { $month }) and not($syslog_rfc_5424)){
		#We changed year to January
		$year = $year + 1;
		$first_log_month = $month_nbr { $month } ;
	    }
	    elsif($syslog_rfc_5424){
		if ($proto eq 6 or $proto eq 17){
		    print OUTFILE "$src_ip $dst_ip $dst_port $proto $action $day$month$lyear $time $interface\n";
		}
		elsif($proto eq 1){
		    print OUTFILE "$src_ip $dst_ip $icmp_type $proto $action $day$month$lyear $time $interface\n";
		}
		else{
		    die "ERROR ----> Uknown protocol.\n";
		}
	    }
	    else {
		$first_log_month = $month_nbr { $month } ;
	    }
	    if ($proto eq 6 or $proto eq 17){
		print OUTFILE "$src_ip $dst_ip $dst_port $proto $action $day$month$year $time $interface\n";
		$printcount ++;
	    }
	    elsif($proto eq 1){
		print OUTFILE "$src_ip $dst_ip $icmp_type $proto $action $day$month$year $time $interface\n";
		$printcount ++;
	    }
	    else{
		die "ERROR ----> Uknown protocol.\n";
	    }
	}
    }
    elsif ($l_filter_result eq -1){
	print "ERROR ----> print_logdata(): Error during the filtering process please contact the author of the script for further troubleshooting.\n";
	exit;
    }
    else{
	# This value is 0 we do not print the log entry
    }
}

sub get_filter_type {
    print "INFO   ----> You have requested to filter the original logfile:\n",
	"What type of filter do you want to apply ?:\n",
	"\t - 1 for source IP address\n",
	"\t - 2 for destination IP address\n",
	"\t - 3 for port\n",
	"\t - 4 for Firewall rule\n",
	"Please enter your choice :";
    my $input = <STDIN>;
    print "\n Input : $input\n";
    chomp $input;
    $filter=2;
    #$filter_ip = $_;
    die;
}

sub validate_ipv4{
    if ($debug eq "255"){
        print "DEBUG :validate_ipv4      :\t----> Validating IPv4 ip address for IP @_\n";
    }
    my $IP_Address = shift ;
    if( $IP_Address =~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)$/ ) {
        if($debug eq "255") {
            print "DEBUG :validate_ipv4      :\t----> IP Address $IP_Address  -->  VALID FORMAT! \n";
        }
        if($1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255)
        {
            if ($debug eq "255"){
                print "DEBUG :validate_ipv4      :\t----> IP address:  $1.$2.$3.$4  -->  All bytes within range\n";
            };
        }
        else
        {
            if ($debug eq "255"){
                print "DEBUG :validate_ipv4      :\t----> IPv4 address had bytes out of range.\n";
        }
            return 0;
        };
        #Address within normal IP Ranges... now checking the multicast status
        if($1 >= 224){
            #This is a multicast IP address
            if ($debug eq "255"){
                print "DEBUG :validate_ipv4      :\t----> This is a multicast IPv4 address.\n";
            }
            return 2;
        }
        else{
            if ($debug eq "255"){
                print "DEBUG :validate_ipv4      :\t----> This is a regular IPv4 address.\n";
            }
            return 1;
        }
    }
    else
    {
        if ($debug eq "255"){
                print "DEBUG :validate_ipv4      :\t----> IPv4 address does not have the right format.\n";
        }
        return -1;
    };
};


sub get_ip_addresses {
    # this procedure is to get all the ip addresses sources and destination for the filtering.
}


sub progress_bar {
    if ($debug eq 0){
	my ( $got, $total, $width, $char ) = @_;
	$width ||= 25; $char ||= '=';
	my $num_width = length $total;
	sprintf "INFO   ----> |%-${width}s| Analysed %${num_width}s lines of %s (%.2f%%)\r",
	    $char x (($width-1)*$got/$total). '>',
	    $got, $total, 100*$got/+$total;
    }
    else{
	print "DEBUG  ----> progress_bar()\t: We are printing the progress bar.\n";
    }
}


sub validate_filter_data{
    #
    # Filter Bitmask are :
    #  - ACL-Name	= 0x0200  = 512
    #  - Interface	= 0x0100  = 256
    #  - hostname 	= 0x0080  = 128
    #  - Date		= 0x0040  =  64
    #  - Time 		= 0x0020  =  32
    #  - IP		= 0x0010  =  16
    #  - SRC_IP		= 0x0008  =   8
    #  - DST_IP		= 0x0004  =   4
    #  - Protocol	= 0x0002  =   2
    #  - Port 		= 0x0001  =   1
    #
    #
    # Procedure which will initialise all the filter data based on existing command line arguments
    if($debug eq "255"){
	print "DEBUG  ----> validate_filter_data(): Entering procedure to validate the filter data.\n";
    }
    if (not(defined($filter))){
	$filter = 0;
	print "DEBUG  ----> validate_filter_data(): Setting \$filter = $filter\n" if ($debug eq "255");
    }
    if(not(defined($filter_exp))){
	$filter_exp=0;
	print "DEBUG  ----> validate_filter_data(): Setting \$filter_exp = $filter_exp\n" if ($debug eq "255");
    }

    if(not(defined($filter_acl))){
	$filter_acl="";
	print "DEBUG  ----> validate_filter_data(): Setting \$filter_acl = $filter_acl\n" if ($debug eq "255");
    }
    else{
	$filter_mask = $filter_mask ^ 512;
	$filter = 2;
	print "DEBUG  ----> validate_filter_data(): Current ACL filter is : $filter_acl\n" if ($debug eq "255");
    }

    if(not(defined($filter_interface))){
	$filter_interface="";
	print "DEBUG  ----> validate_filter_data(): Setting \$filter_fw = $filter_interface\n" if ($debug eq "255");
    }
    else{
	$filter_mask = $filter_mask ^ 256;
	$filter = 2;
	print "DEBUG  ----> validate_filter_data(): Current Interface filter is : $filter_interface\n" if ($debug eq "255");
    }

    if(not(defined($filter_fw))){
	$filter_fw= "";
	print "DEBUG  ----> validate_filter_data(): Setting \$filter_fw = $filter_fw\n" if ($debug eq "255");
    }
    else{
	$filter_mask = $filter_mask ^ 128;
	$filter = 2;
	print "DEBUG  ----> validate_filter_data(): Current Firewall filter is : $filter_fw\n" if ($debug eq "255");
    }

    ### Filter Time Mask = 64
    if(not(defined($filter_date))){
	$filter_date="";
    	$filter_date = $filter_day = $filter_month = "";

    	print "DEBUG  ----> validate_filter_data(): Initialising variable \$filter_date= $filter_date\n" if ($debug eq "255");
    }
    else{
	print "DEBUG  ----> validate_filter_data(): Current variable \$filter_date = $filter_date\n" if ($debug eq "255");
	if($filter_date =~ m/\d{2}-\d{2}-\d{4}/){
	    #We have a good date format
	    $filter_day = $filter_month = $filter_year = $filter_date;
	    $filter_day =~ s/^(\d{2})-.+/$1/;
	    $filter_month =~ s/..-(\d{2})-.+/$1/;
	    $filter_year =~ s/.+(\d{4})$/$1/;
	    $filter_mask = $filter_mask ^ 64;
	    if($debug eq "255"){
		print "DEBUG  ----> validate_filter_data \t: Month: $filter_month day: $filter_day Year : $filter_year\n";
	    }
	    if (($filter_day >= 1) and ($filter_day <=31)){
		$filter=2;
	    }
	    else{
		print "\nERROR ----> Day value $filter_day out of range.\n";
		exit;
	    }
	    if (($filter_month >= 1) and ($filter_month <= 12)){
		$filter=2;
	    }
	    else{
		print "\nERROR ----> Month value $filter_month out of range.\n";
		exit;
	    }
	}
	else{
	    print "\nERROR ----> You have entered an invalid date";
	    exit;
	}
    }

    ### Filter Time Mask = 32
    if(not(defined($filter_time))){
	$filter_time = "";
	$filter_time_type = "none";
	print "DEBUG  ----> validate_filter_data(): Initialising variable \$filter_time = $filter_time\n" if ($debug eq "255");
    }
    else{
	print "DEBUG  ----> validate_filter_data(): Current variable \$filter_time = $filter_time\n" if ($debug eq "255");
	my @l_filter_time = split (":",$filter_time);
	$filter_mask = $filter_mask ^ 32;
	$filter_time_hours = $l_filter_time[0];
	$filter_time_minutes = $l_filter_time[1];
	$filter_time_seconds = $l_filter_time[2];
	if($debug eq "255"){
	print "DEBUG  ----> validate_filter :\t: Parameters for time:\n";
	my $i=0;
	print "DEBUG  ----> validate_filter :\t: List of time arguments when the procedure was called.:\n";
	foreach (@_){
	    print "DEBUG  ----> validate_filter :\t:\t$i:$_ \n";
	    $i++;
	}
    }
	if($filter_time =~ m/([01][0-9]|2[0-3]):([0-5]?[0-9]|\*):([0-5]?[0-9]|\*)/){
	    # We have a good time definition
	    if ($debug eq "255" and ($filter_time_minutes eq "*" or $filter_time_seconds eq "*")){
		print "DEBUG  ----> validate_filter_data \t : The time had been matched correctly and is hours : $filter_time_hours minutes $filter_time_minutes seconds $filter_time_seconds.\n",
		    "DEBUG  ----> \n";
	    }
	    if ($filter_time_minutes =~ m/\*/ or $filter_time_seconds =~ m/\*/){
		$filter_time_type = "advanced";
		print "DEBUG  ----> validate_filter_data \t : Setting \$filter_time_type to $filter_time_type\n" if ($debug eq "255");
	    }
	    else{
		$filter_time_type = "simple";
		print "DEBUG  ----> validate_filter_data \t : Setting \$filter_time_type to $filter_time_type\n" if ($debug eq "255");
	    }
	    $filter=2;
	}
	else{
	    print "\nERROR ----> You have entered an invalid time.\n",
		"ERROR  ----> Time format is HH:<MM|*>:<SS:*>.\n";
	    exit;
	}
    }


    if(not(defined($filter_ip))){
	$filter_ip="";
	print "DEBUG  ----> validate_filter_data(): Initialising variable \$filter_ip = $filter_ip\n" if ($debug eq "255");
    }
    else{
	print "DEBUG  ----> validate_filter_data(): Current \$filter_ip is $filter_ip\n",
	    "DEBUG  ----> validate_filter_data(): Calling validate_subnet procedure to check if IP is a subnet.\n" if ($debug eq "255");
	my $ip_valid = 0;
	my ($l_is_subnet,$l_ip_address,$l_ip_bitmask) = validate_subnet($filter_ip);
	print "DEBUG  ----> validate_filter_data(): We have received reply with the following data L_IS_subnet = $l_is_subnet, l_ip_address = $l_ip_address, bitMask = $l_ip_bitmask\n" if ($debug eq "255");
	$filter_ip_is_subnet = $l_is_subnet;
	if ($filter_ip_is_subnet){
	    $filter_ip = $l_ip_address;
	    $filter_ip_bitmask = $l_ip_bitmask;
	}
	else{
	    $ip_valid = validate_ipv4($filter_ip);
	}

	if ($ip_valid eq 1 or $filter_ip_is_subnet eq 1){
	    $filter=2;
	    $filter_mask = $filter_mask ^ 16;
	}
	elsif($ip_valid eq 2 and $filter_ip_is_subnet eq 1){
	    print "WARNING ----> You are filtering on a Multicast IPv4 address.\n";
	    $filter=2;
	    $filter_mask = $filter_mask ^ 16;
	}
	else{
	    print "\nERROR ----> Invalid IP address defined as filter : -filter_ip $filter_ip. \n",
		"Please verify your parameters\n Good bye\n";
	    exit;
	}
    }


    if(not(defined($filter_src_ip))){
	$filter_src_ip="";
	print "DEBUG  ----> validate_filter_data(): Setting \$filter_src_ip = $filter_src_ip\n" if ($debug eq "255");
    }
    else{
	print "DEBUG  ----> validate_filter_data(): Current \$filter_src_ip is $filter_src_ip\n" if ($debug eq "255");
	my $ip_valid = 0;
	my ($l_src_is_subnet, $l_src_ip_address, $l_src_ip_bitmask) = validate_subnet($filter_src_ip);

	$filter_src_ip_is_subnet = $l_src_is_subnet;
	if ($filter_src_ip_is_subnet){
	    $filter_src_ip = $l_src_ip_address;
	    $filter_src_ip_bitmask = $l_src_ip_bitmask;
	}
	else{
	    $ip_valid = validate_ipv4($filter_src_ip);
	}
	if ($ip_valid eq 1 or $filter_src_ip_is_subnet eq 1){
	    $filter=2;
   	    $filter_mask = $filter_mask ^ 8;
	}
	elsif($ip_valid eq 2 and $filter_src_ip_is_subnet eq 1){
	    print "WARNING ----> You are filtering on a Multicast IPv4 address.\n";
	    $filter=2;
	    $filter_mask = $filter_mask ^ 8;
	}
	else{
	    print "\nERROR ----> Invalid IP address defined as filter : -filter_src_ip $filter_src_ip. \n",
		"Please verify your parameters\n Good bye\n";
	    exit;
	}
    }

    if(not(defined($filter_dst_ip))){
	$filter_dst_ip="";
	print "DEBUG  ----> validate_filter_data(): Initialising variable \$filter_dst_ip = $filter_dst_ip\n" if ($debug eq "255");
    }
    else{
	print "DEBUG  ----> validate_filter_data(): Current \$filter_dst_ip is $filter_dst_ip\n" if ($debug eq "255");
	my $ip_valid = 0;
	my ($l_dst_is_subnet, $l_dst_ip_address, $l_dst_ip_bitmask) = validate_subnet($filter_dst_ip);

	$filter_dst_ip_is_subnet = $l_dst_is_subnet;
	if ($filter_src_ip_is_subnet){
	    $filter_dst_ip = $l_dst_ip_address;
	    $filter_dst_ip_bitmask = $l_dst_ip_bitmask;
	}
	else{
	    $ip_valid = validate_ipv4($filter_dst_ip);
	}
	if ($ip_valid eq 1 or $filter_dst_ip_is_subnet eq 1){
	    $filter=2;
   	    $filter_mask = $filter_mask ^ 4;
	}
	elsif($ip_valid eq 2 and $filter_dst_ip_is_subnet eq 1){
	    print "WARNING ----> You are filtering on a Multicast IPv4 address.\n";
	    $filter=2;
	    $filter_mask = $filter_mask ^ 4;
	}
	else{
	    print "\nERROR ----> Invalid IP address defined as filter : -filter_dst_ip $filter_dst_ip. \n",
		"Please verify your parameters\n Good bye\n";
	    exit;
	}
    }

    if(not(defined($filter_port))){
	$filter_port="";
	print "DEBUG  ----> validate_filter_data(): Initialising variable \$filter_port = $filter_port\n" if ($debug eq "255");
    }
    else{
	print "DEBUG  ----> validate_filter_data(): Current variable \$filter_port = $filter_port\n" if ($debug eq "255");
	$filter=2;
	$filter_mask = $filter_mask ^ 1;
    }

    if(not(defined($filter_proto))){
	$filter_proto="";
	print "DEBUG  ----> validate_filter_data(): Initialising variable \$filter_proto = $filter_proto\n" if ($debug eq "255");
    }
    else{
	print "DEBUG  ----> validate_filter_data(): Current variable \$filter_proto = $filter_proto\n" if ($debug eq "255");
	if (0 < $filter_proto and $filter_proto < 255){
	    $filter=2;
	    $filter_mask = $filter_mask ^ 2;
	}
	else{
	    print "ERROR  ----> validate_filter_data(): Invalid Protocol ID : $filter_proto.\n";
	    exit;
	}
    }

    print "DEBUG  ----> validate_filter_data(): Current variable \$filter_mask = $filter_mask\n" if ($debug eq "255");
}

sub ip_to_bin {
    my ($ip) = shift;
    # v4 -> return 32-bit array
    return unpack('B32', pack('C4C4C4C4', split(/\./, $ip)));
}

sub bin_to_ip {
    my ($binip) = shift;
    # Define normal size for address
    my $len = 32;
    # Prepend 0s if address is less than normal size
    $binip = '0' x ($len - length($binip)) . $binip;
    return join '.', unpack('C4C4C4C4', pack('B32', $binip));
}

sub validate_subnet{
    my $l_ip_to_validate = shift;
    print "DEBUG  ----> validate_subnet()\t\t: print l_ip_to_validate = $l_ip_to_validate\n" if ($debug eq "255");
    my ($lv_is_subnet, $lv_ip_address, $lv_ip_mask, $lv_ip_bitmask) = "";
    if ($l_ip_to_validate =~ m/(.+)\/(.+)/){
	#this ip contain a subnet
	$lv_ip_address = $1;
	$lv_ip_mask = $2;
	if ($debug eq "255"){
	    print "DEBUG  ----> validate_subnet()\t\t: We have a subnet $l_ip_to_validate\n",
		"DEBUG  ----> validate_subnet()\t\t: IP Address : $lv_ip_address\n",
		"DEBUG  ----> validate_subnet()\t\t: IP Mask    : $lv_ip_mask\n";
	}

	my @la_ip_mask_split = split (/\./,$lv_ip_mask);
	my $la_ip_mask_split_size = @la_ip_mask_split;
	if ($la_ip_mask_split_size eq 1){
	    #We have a bitmask
	    $lv_ip_mask =~ s/^([0-32]).+/$1/;
	    $lv_ip_bitmask = $lv_ip_mask;
	}
	elsif($la_ip_mask_split_size > 1){
	    $lv_ip_mask =~ s/^([0-255]\.[0-255]\.[0-255]\.[0-255]).+/$1/;
	    #We have a netmask
	    $lv_ip_bitmask = $netmask_to_bitmask{$lv_ip_mask};
	}
	else{
	    #This is an invalid netmask quitting the program.
	    print "ERROR  ----> The netmask or bitmask $lv_ip_mask specified is invalid.\n";
	    exit;
	}
	my $lv_bin_ip_address = ip_to_bin($lv_ip_address);
	my $lv_bin_ip_netmask = ip_to_bin($bit_to_netmask{$lv_ip_bitmask});

	$lv_bin_ip_address = $lv_bin_ip_address & $lv_bin_ip_netmask;
	my $lv_ip_net_address = bin_to_ip($lv_bin_ip_address);
	print "DEBUG  ----> validate_subnet()\t: Procedure validate subnet is finishing values are : \n",
	    "DEBUG  ----> validate_subnet()\t: \t l_bin_ip_address = $lv_bin_ip_address\n",
	    "DEBUG  ----> validate_subnet()\t: \t l_bin_ip_bitmask = $lv_bin_ip_netmask\n",
	    "DEBUG  ----> validate_subnet()\t: \t l_ip_net_address = $lv_ip_net_address\n" if ($debug eq "255");
	$lv_ip_address = $lv_ip_net_address;
	$lv_is_subnet = 1;
    }
    else{
	$lv_is_subnet = 0;
	$lv_ip_address = $l_ip_to_validate;
	$lv_ip_bitmask = 32;
    }
    my @return_param = ($lv_is_subnet, $lv_ip_address, $lv_ip_bitmask);
    if ($debug eq "255"){
	my $i = 0;
	foreach (@return_param){
	    print "DEBUG  ----> validate_subnet() \t\t:\t$i:$_ \n";
	    $i++;
	}
    }

    return @return_param;
}
sub print_usage {
    print "\n Program \t: syslog to TSS converter",
        "\n Author  \t: Stephane PEREZ",
        "\n Date \t\t: ".$prog_date."\n\r",
        "\n Version \t: ".$prog_version. "\n\r",
        "\n Usage : syslog_to_tss_converter.pl -file <filename> -output {APG|TSS} [-fileout <filename>] [-yearstart {year value}] [-debug {0-255}]\n",
	#"\t\t\t-filter -filter_exp 'use PCAP syntax for filtering'\n",
	"\t\t\t[-filter_fw {FW Nane}] \n",
	"\t\t\t[-filter_acl {ACL_Name}] \n",
	"\t\t\t[-filter_src_ip {<IP Address or Subnet>}] \n",
	"\t\t\t[-filter_dst_ip {<IP Address or Subnet>}] \n",
	"\t\t\t[-filter_ip {<IP Address or Subnet>}] \n",
	"\t\t\t[-filter_port {1-65535}] \n",
	"\t\t\t[-filter_proto {1-255}] \n",
	"\t\t\t[-filter_date {DD-MM-YYYY}] \n",
	"\t\t\t[-filter_time {HH:MM:SS}] \n\n\n",
        "Parameters details:\n",
	"\tParameters between '[ ]' are optionals\n\n",
        "\toutput \t\t: Provide the output either TSS Historical rule usage format or APG import like format.\n",
        "\tyearstart\t: Used to calculate the accurate log entry date from the beginning of the file\n",
	"\tfileout \t: In case a user want to override the default filename enter the expected output file name.\n",
	"\n\tFilter usage details for simple filtering values used with (filter_src_ip or filter_dst_ip or filter_ip)\t:\n",
	"\t\t" . 'Use a regular IP address' . "\t: " . '192.168.1.1' . "\n",
	"\t\t" . 'Use a subnet with bitmask' . "\t: " . '192.168.1.0/24' . "\n",
	"\t\t" . 'Use a subnet with netmask' . "\t: " . '192.168.1.0/255.255.255.0' . "\n",
	"\taACL_Name \t: For ACL filtering, use the ACL name on Cisco, for SRX ACL filtering means rule number. \n",
        "\nThe file format detection is automatic and is compatible with : Cisco firewalls, Fortinet Fortigate, SonicWall, Safe\@Office devices. \n",
        "\n\nFor SonicWall devices the file uses the following input data :",
        " The input file is a tcpdump of the syslog flow: \n\t tcpdump -i eth0 -s0 -v dst port 514 and host <firewall_ip> | grep Msg > /tmp/sonicwall.syslog. \n\n\n",
	#"For IP Address filtering with expression you can use the following syntax:\n",
	#"\tHost IP\t : 172.31.0.1\n",
	#"\tSubnet \t : 192.168.0.0/16 or 192.168.0.0/255.255.255.0\n",
	#"\tIP Range : 192.168.0.1-192.168.0.20\n",
	#"\tCombination separated by commas eg. \n",
	#"\t\t -filter_ip '172.31.0.1, 172.31.1.0/24, 172.31.2.0/255.255.255.0, 192.168.1.0-192.168.1.20'\n\n",
	#"For Protocol filtering enter\t: TCP, UDP, ICMP, IPv6, or 1, 6, 17 \n",
	#"For Port filtering enter \t: TCP/23, UDP/53, TCP/23-25\n\n",
        "Goodbye!\n";
}
