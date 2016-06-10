Perl Scripts
============

The following scripts demonstrate the ability to generate APG log format files in order to execute APG jobs based on historical rule usage data.


Installation Instructions
-------------------------
Have a perl interpreter on your local computer

Copy the script and then use it with the following parameters.

Usage : syslog_to_tss_converter.pl -file <filename> -output {APG|TSS} [-fileout <filename>] [-yearstart {year value}] [-debug {0-255}]
			[-filter_fw {FW Nane}] 
			[-filter_acl {ACL_Name}] 
			[-filter_src_ip {<IP Address or Subnet>}] 
			[-filter_dst_ip {<IP Address or Subnet>}] 
			[-filter_ip {<IP Address or Subnet>}] 
			[-filter_port {1-65535}] 
			[-filter_proto {1-255}] 
			[-filter_date {DD-MM-YYYY}] 
			[-filter_time {HH:MM:SS}] 


Parameters details:
	Parameters between '[ ]' are optionals

	output 		: Provide the output either TSS Historical rule usage format or APG import like format.
	yearstart	: Used to calculate the accurate log entry date from the beginning of the file
	fileout 	: In case a user want to override the default filename enter the expected output file name.

	Filter usage details for simple filtering values used with (filter_src_ip or filter_dst_ip or filter_ip)	:
		Use a regular IP address	: 192.168.1.1
		Use a subnet with bitmask	: 192.168.1.0/24
		Use a subnet with netmask	: 192.168.1.0/255.255.255.0

The file format detection is automatic and is compatible with : Cisco firewalls, Fortinet Fortigate, SonicWall, Safe@Office devices. 


For SonicWall devices the file uses the following input data : The input file is a tcpdump of the syslog flow: 
	 tcpdump -i eth0 -s0 -v dst port 514 and host <firewall_ip> | grep Msg > /tmp/sonicwall.syslog. 

 

Help
----
Please contact support@tufin.com or stephane.perez@tufin.com