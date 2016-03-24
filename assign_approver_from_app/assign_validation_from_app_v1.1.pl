#!/usr/bin/perl
use lib '../extlib/lib/perl5';
use lib './extlib/lib/perl5';
use lib '/opt/tufin/securitysuite/ps/perl/extlib/lib/perl5';
use lib '../Tufin_Modules/lib';
use strict;
use warnings;
# Standard libs
use Getopt::Long;
use MIME::Base64;
use REST::Client;
use JSON;
require XML::LibXML;
use Config::Simple;

use Data::Dumper;
$Data::Dumper::Indent = 1;


###########################################################################################################
#
#This Perl Script is to Export the list of authorised and unauthorised revisions from Tufin SecureTrack.
#
#
##########################################################################################################
#
# Author		: Stephane PEREZ
# Contact		: stephane.perez@tufin.com
#
##################################
#
# Revisions
#
# - Version 1.0    : Initial creation of the script
# - Version 1.1    : Adding possibility that an application does not have any approval
#
#
#############################
#   TODO
#

#
##################################

use vars qw ($debug $help $testing);

my $prog_date    	= "12 June 2015";
my $prog_version        = "1.1";
my $start_run = time(); # We want to know how much time it took for the script to run (just for fun)

#Retrieving additional parameters.

GetOptions(
	"debug"			=> \$debug,
        "help"        		=> \$help,
        );

# Global vars


if (not defined ($debug)) {
	$debug = 0;
}

print "INFO\nINFO  ----> Welcome to the assign_validation_from_app script version $prog_version.\n",
    "INFO  ---->\n" if $debug eq 255;


# Retrieving data from configuration file
my $cfg = new Config::Simple('/opt/tufin/securitysuite/ps/perl/api.cfg');

my $st_host = $cfg->param("securetrack.host");
my $st_user = $cfg->param("securetrack.user");
my $st_pass = $cfg->param("securetrack.pass");

my $sc_host = $cfg->param("securechange.host");
my $sc_user = $cfg->param("securechange.user");
my $sc_pass = $cfg->param("securechange.pass");

my $verify_hostname = $cfg->param("ssl.certificate-check");

my $exec_step_cfg = $cfg->param("assign_validation_from_app.steps");
my $exec_step_type = ref($exec_step_cfg); #Need to handle the Array when multiple steps are used

my $debug = $cfg->param("debug.level");

#Variable Sanity Check
my $error_code = 0;
my $ticket_id = 0;

# Prepare Rest::Client for SecureTrack
my $st_client = REST::Client->new(host => $st_host);
my $st_encoded_auth = encode_base64("$st_user:$sc_pass", '');
$st_client->addHeader( "Authorization", "Basic $st_encoded_auth");
$st_client->addHeader( "Accept", "application/json" );
$st_client->addHeader( "Accept", "application/xml" );
$st_client->addHeader( "Content-Type", "application/xml");

# Prepare Rest::Client for SecureChange
my $sc_client = REST::Client->new(host => $sc_host);
my $sc_encoded_auth = encode_base64("$sc_user:$sc_pass", '');
$sc_client->addHeader( "Authorization", "Basic $sc_encoded_auth");
$sc_client->addHeader( "Accept", "application/json" );
$sc_client->addHeader( "Accept", "application/xml" );
$sc_client->addHeader( "Content-Type", "application/xml");


###############################################################################
###############################################################################
#
# Main routine:
#
#
#
###############################################################################

print "DEBUG ----> Initialisation completed, starting main routine.\n";

my 	$api_xml_param 	= <STDIN>;
chomp 	$api_xml_param;
$ticket_id 	= scw_api_ticket_id($api_xml_param);

my $json_ticket_data = scw_get_ticket_data(\$ticket_id);
if (validate_current_step(ticket_data => $json_ticket_data, exec_step => $exec_step_cfg)) {
	#code
	my $app_id = scw_parse_app_in_ticket(\$json_ticket_data);
	my ($r_pre_approval_required, $r_pre_approval_group) = get_valgroup_from_app(\$app_id);
	if ($$r_pre_approval_required eq 0) {
		# we haven't found the pre-approval group
		print "INFO --> approving Ticket from API with user : $sc_user\n" if $debug eq 255;
		my $user_id = search_scw_user_id(\$sc_user);
		my $error_code = approve_ticket(TicketID=> \$ticket_id, TicketData => $json_ticket_data,
			       UserID=>$user_id,
			       Comment=>"No Approval Needed");
		if ($error_code ne 1) {
			print "ERROR ----> An error occurs during the execution of the script while approving the ticket.\n";
			exit 0 ;
		}

	}
	else{
		my $user_id = search_scw_user_id($r_pre_approval_group);
		if ($user_id > 0 ) {
			if (reassign_ticket(TicketID => \$ticket_id, TicketData => $json_ticket_data, UserID=>$user_id,
					    Comment=>"Reassign by Tufin API for application")) {
			}
		}
		else{
			print "ERROR ----> User not found\n";
			exit 0;
		}
	}
}
my $end_run = time();
my $run_time = $end_run - $start_run;

print "\nINFO\nINFO\n",
    "INFO ----> Program terminated successfully in : $run_time seconds.\n",
    "\n\n",
    "Good Bye !\n";

exit $error_code;


###############################################################################
#
# API HELPERS
#

######################################
###### API Helper and sub procedures

sub approve_ticket{
	#Procedure executed to approve a ticket by the API.
	# Approval XML to send.
	# URL : https://scw_IP/securechangeworkflow/api/securechange/tickets/<ticket_ID>/steps/current/tasks/<task_ID>
	#<task>
	#   <id>1454</id>
	#   <assignee>18</assignee>
	#   <status>DONE</status>
	#   <fields>
	#      <field xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="approve_reject">
	#      <id>12727</id>
	#      <name>Approve Access Request</name>
	#     <approved>true</approved>
	#      <reason>OK by API</reason>
	#       </field>
	#   </fields>
	#</task>

	my %l_h_args = @_;
	my $l_ticket_data = $l_h_args{TicketData};
	my $l_user_id 	= $l_h_args{UserID};
	my $l_ticket_id = $l_h_args{TicketID};
	my $l_approval_comment = $l_h_args{Comment};
	my $return_code = -1;

	#Getting JSON data to construct XML structure

	my @l_ticket = $l_ticket_data->{'ticket'};
	my $l_ticket_current_step = $l_ticket[0]->{'current_step'}{'id'};
	my $l_task_id = 0;
	my $l_approve_field_id = 0;
	my $l_approve_field_name = "";

	for my $step (@{$l_ticket[0]->{'steps'}{'step'}}){
                if ($step->{'id'} eq $l_ticket_current_step) {
                        $l_task_id = $step->{'tasks'}{'task'}{'id'};
			for my $field (@{$step->{'tasks'}{'task'}{'fields'}{'field'}}){
				if ($field->{'@xsi.type'} eq 'approve_reject') {
					$l_approve_field_id = $field->{'id'};
					$l_approve_field_name = $field->{'name'};
				}
			}
                }
        }
	if (($l_task_id ne 0) and ($l_approve_field_id ne 0)) {
		#Constructing XML structure
		my $o_new_dom = XML::LibXML::Document->new('1.0', 'UTF-8');
		my $o_new_root= XML::LibXML::Element->new('task');

		$o_new_dom->setStandalone(1);
		$o_new_dom->addChild($o_new_root);

		my $o_task_id = XML::LibXML::Element->new('id');
		$o_task_id->appendText($l_task_id);
		$o_new_root->addChild($o_task_id);

		my $o_assignee_id = XML::LibXML::Element->new('assignee');
		$o_assignee_id->appendText($l_user_id);
		$o_new_root->addChild($o_assignee_id);

		my $o_status = XML::LibXML::Element->new('status');
		$o_status->appendText('DONE');
		$o_new_root->addChild($o_status);

		my $o_fields_list = XML::LibXML::Element->new('fields');
		$o_new_root->addChild($o_fields_list);

		my $o_field_approve = XML::LibXML::Element->new('field');
		$o_field_approve->setAttribute('xmlns:xsi' => "http://www.w3.org/2001/XMLSchema-instance");
		$o_field_approve->setAttribute('xsi:type' => "approve_reject");
		$o_fields_list->addChild($o_field_approve);

		my $o_field_approve_id = XML::LibXML::Element->new('id');
		$o_field_approve_id->appendText($l_approve_field_id);
		$o_field_approve->addChild($o_field_approve_id);

		my $o_field_approve_name = XML::LibXML::Element->new('name');
		$o_field_approve_name->appendText($l_approve_field_name);
		$o_field_approve->addChild($o_field_approve_name);

		my $o_field_approve_reason = XML::LibXML::Element->new('reason');
		$o_field_approve_reason->appendText($l_approval_comment);
		$o_field_approve->addChild($o_field_approve_reason);

		my $o_field_approve_status = XML::LibXML::Element->new('approved');
		$o_field_approve_status->appendText('TRUE');
		$o_field_approve->addChild($o_field_approve_status);

		my $xml_string = $o_new_dom->toString;

		my $url = "/securechangeworkflow/api/securechange/tickets/$$l_ticket_id/steps/current/tasks/$l_task_id";
		$sc_client->PUT($url, $xml_string);
		if ($sc_client->responseCode() ne "200") {
			print "ERROR ----> approve_ticket " . __LINE__ ,
				"----> Error during API call while assigning the group to the ticket : " . $sc_client->responseCode(),
				"\n";
			exit 1;
		}
		return 1;
	}
	else{
		return -1;
	}
}

sub reassign_ticket{
	my %l_h_args 	= @_;
	my $l_ticket_data = $l_h_args{TicketData};
	my $l_user_id 	= $l_h_args{UserID};
	my $l_reassign_comment = $l_h_args{Comment};
	my $l_ticket_id = $l_h_args{TicketID};
	my $return_code = -1;

	#https://10.100.5.88/securechangeworkflow/api/securechange/tickets/1/steps/2/tasks/2/reassign/15
	#PUT
	#Body:
	#<reassign_task_comment>
	#<comment>bla bla</comment>
	#</reassign_task_comment>
	#
	#15 is id of group

	my $o_new_dom = XML::LibXML::Document->new('1.0','UTF-8');
	my $o_new_root = XML::LibXML::Element->new('reassign_task_comment');
	$o_new_dom->setStandalone(1);
	$o_new_dom->addChild($o_new_root);

	my $o_comment = XML::LibXML::Element->new('comment');
	$o_new_root->addChild($o_comment);
	$o_comment->appendText($l_reassign_comment);

	my $xml_string = $o_new_dom->toString;

	#XML structure is ready.
	#Getting JSON data to construct URL for query.
	my @l_ticket = $l_ticket_data->{'ticket'};
	my $l_ticket_current_step = $l_ticket[0]->{'current_step'}{'id'};
	my $l_task_id = 0;
	for my $step (@{$l_ticket[0]->{'steps'}{'step'}}){
		if ($step->{'id'} eq $l_ticket_current_step) {
			$l_task_id = $step->{'tasks'}{'task'}{'id'};
		}
	}
	my $url = "/securechangeworkflow/api/securechange/tickets/$$l_ticket_id/steps/$l_ticket_current_step/tasks/$l_task_id/reassign/$l_user_id";
	$sc_client->PUT($url , $xml_string);
	if ($sc_client->responseCode() ne "200") {
		print "ERROR ----> reassign_ticket " . __LINE__ ,
			"----> Error during API call while assigning the group to the ticket : " . $sc_client->responseCode(),
			"\n";
		exit 1;
	}
}

sub search_scw_user_id{
	#Procedure to get a user ID in SecureChange for ticket reassignment
	my $rl_user_name = shift;
	my $url = "/securechangeworkflow/api/securechange/users.json";
	$sc_client->GET($url);
	if ($sc_client->responseCode() ne "200") {
		print "ERROR ----> search_scw_user_id " . __LINE__ ,
			"----> Error during API call while retrieving user list with error Code : " . $sc_client->responseCode(),
			"\n";
		exit 1;
	}
	my $l_json_user_data = decode_json($sc_client->responseContent());
	for my $userdata (@{$l_json_user_data->{'users'}{'user'}}){
		if ($userdata->{'name'} eq $$rl_user_name) {
			return $userdata->{'id'};
		}
	}
	return -1;
}

sub validate_current_step{
	my %l_h_args 	= @_;
	my $return_code = 0;
	my $json_ticket_data 	= $l_h_args{ticket_data};
	my $l_exec_step 	= $l_h_args{exec_step};
	my @l_ticket 	= $json_ticket_data->{'ticket'};
	my $l_cur_step_name 	= $l_ticket[0]->{current_step}{'name'};
	my $l_cur_step_id   	= $l_ticket[0]->{current_step}{'id'};
	if ((index $l_exec_step,$l_cur_step_name) >= 0 ) {
		return 1;
	}
	else{
		return 0;
	}
}

sub scw_get_ticket_data{
	my $r_ticket_id = shift;
	my $url = "/securechangeworkflow/api/securechange/tickets/$$r_ticket_id.json";
	$sc_client->GET($url);
	if ($sc_client->responseCode() ne "200") {
		print "ERROR ----> scw_parse_ticket " . __LINE__ ,
			"----> Error during API call while retrieving ticket data with error Code : " . $sc_client->responseCode(),
			"\n";
		exit 1;
	}
	my $jsonticket = decode_json($sc_client->responseContent());
	return ($jsonticket);
}

sub get_valgroup_from_app{
	#Procedure called with application ID
	#Retrieve comment and parse the Validation Group
	#Return the Validation Group
	my $l_app_id = shift;
	my $l_app_comment = sap_get_application_comment($$l_app_id);
	my $xmlparser = XML::LibXML->new();
	$xmlparser->validation(0);
	my $tree = $xmlparser->parse_string($l_app_comment);
	my $root = $tree->getDocumentElement;
	my $l_validation_required = $root->getElementsByTagName('pre-validation')->[0]->getFirstChild->getData;
	my $l_validation_group = $root->getElementsByTagName('pre-validation-group')->[0]->getFirstChild->getData;
	if($l_validation_required == 0){
		return \0;
	}
	elsif ($l_validation_required == 1 and not defined $l_validation_group) {
		#There is an error in the Application definition
		print "ERROR ----> No Validation group defined, considering no validation.\n";
		exit 1;
	}
	else{
		return (\$l_validation_required, \$l_validation_group);
	}
}


sub sap_get_application_comment{
	#Retrieve comment for an Application using application ID
	# Return command in native form
	my $l_app_id = shift;
	my $url = "/securechangeworkflow/api/secureapp/repository/applications/$l_app_id.json";
	$sc_client->GET($url);
	if ($sc_client->responseCode() ne "200") {
	print "ERROR ----> sap_get_application_comment " . __LINE__ ,
		"----> Error during API call while retrieving application data $l_app_id with error Code : " . $sc_client->responseCode(),
		"\n";
	exit 1;
	}
	my $l_jsonapp = decode_json($sc_client->responseContent());
	my @l_application = @{ $l_jsonapp->{'application'} };
	my $l_app_comment = $l_application[0]->{'comment'};
	$l_app_comment =~s/\n//g;
        $l_app_comment =~s/^.*<Custom>(.+)<\/Custom>.*/<Custom>$1<\/Custom>/;
        my $xml_header = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
        return $xml_header.$l_app_comment;
}

sub scw_parse_app_in_ticket{
	my $jsonticket = shift;
	my $appid = $$jsonticket->{'ticket'}{'application_details'}{'id'};
	return $appid;
}


sub scw_api_ticket_id{
	my $l_api_call = shift;
	if ($l_api_call eq "<ticket_info/>") {
		# This is a test ticket
		print "INFO ----> Scipt called by Test mode.";
		exit 0;
	}
	my $parser = XML::LibXML->new();
	my $tree = $parser->parse_string($l_api_call);
	my $root = $tree->getDocumentElement;
	my $l_ticket_id = $root->getElementsByTagName('id')->[0]->getFirstChild->getData;
	print "DEBUG ----> scw_api_ticket_id ----> Ticket id is : $l_ticket_id\n";
	return $l_ticket_id;
}

sub print_usage {
    print "\nHELP has been requested.\n\n Program \t: SecureTrack Unauthorised Revision export script",
        "\n Author  \t: Stephane PEREZ (" . 'stephane.perez@tufin.com'. ")",
        "\n Date \t\t: ".$prog_date."\n\r",
        "\n Version \t: ".$prog_version . "\n\r",
	"\t\t\t[-help]\n",
	"Parameters details:\n",
        "Goodbye!\n";
}
