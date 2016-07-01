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
# This perl script is for processing tickets that needs multiple approvals in a customer system
#
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
#
#
#############################
#   TODO
#
#
##################################

use vars qw ($debug $help $testing);

my $prog_name 		= "valudate_approvals";
my $prog_date    	= "7 March 2016";
my $prog_version        = "1.0";
my $start_run = time(); # We want to know how much time it took for the script to run (just for fun)

#Retrieving additional parameters.

GetOptions(
	"debug"			=> \$debug,
        "help"        		=> \$help,
	"testing=s"		=> \$testing,
        );

# Global vars


if (not defined ($debug)) {
	$debug = 0;
}

print "INFO\nINFO  ----> Welcome to the $prog_name script version $prog_version.\n",
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

my $exec_step_cfg = $cfg->param("validate-approvals.step");
my $exec_step_type = ref($exec_step_cfg); #Need to handle the Array when multiple steps are used
my $approval_steps_cfg = $cfg->param("validate-approvals.users-approval-step");

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


if (defined $testing) {
	$ticket_id = $testing;
}
else{
	my 	$api_xml_param 	= <STDIN>;
	chomp 	$api_xml_param;
	$ticket_id 	= scw_api_ticket_id($api_xml_param);
}

print "DEBUG ----> (main) ----> Getting ticket data.\n" if ($debug eq 255);

my $json_ticket_data = scw_api_get_ticket_data(\$ticket_id);

if (scw_api_validate_current_step(ticket_data => $json_ticket_data, exec_step => $exec_step_cfg)) {
	#code
	#
	my @l_ticket 	= $json_ticket_data->{'ticket'};
	my $l_cur_step_name 	= $l_ticket[0]->{current_step}{'name'};
	my $l_cur_step_id   	= $l_ticket[0]->{current_step}{'id'};
	my $user_id = scw_api_search_user_id(\$sc_user);
	my ($l_return_code,$l_approval_data) = scw_calc_approval_data(TicketData => $json_ticket_data, TicketID => \$ticket_id, ApprovalStepName => \$approval_steps_cfg);

	print "Dumper (main) : L-approval-data : " . Dumper($l_approval_data);
	print "Value for approval data is: " . $l_approval_data->{'Summary'}{'Approved'} . "\n";
	if ($l_approval_data->{'Summary'}{'Approved'}) {

		#This access is approved
		print "DEBUG ----> (main) ----> Access is approved, calling scw_api_approve_ticket\n";
		print "Sending data to procedure : \n";
		print "\tUserID = $user_id\n",
			"\tInformationComment = \"" . $l_approval_data->{'Summary'}{'Approval Comment'} . "\"\n",
			"\tTicketID = " . \$ticket_id . "\n",
			"\tTicketData =  $json_ticket_data\n",
			"\tApprovalComment = \"Approval calculation made by API\"";

		my $error_code = scw_api_approve_ticket(TicketID=> \$ticket_id, TicketData => $json_ticket_data,
			       UserID=>$user_id,
			       InformationComment=>$l_approval_data->{'Summary'}{'Approval Comment'},
			       ApprovalComment=>"Approval calculation made by API.");
	}
	else{
		#Access is not approved
		print "DEBUG ----> (main) ----> Access is denied, calling scw_api_approve_ticket\n";
		print "Sending data to procedure : \n";
		print "\tUserID = $user_id\n",
			"\tInformationComment = $l_approval_data->{'Summary'}{'Approval Comment'}\n",
			"\tTicketID = $ticket_id\n",
			"\tTicketData =  $json_ticket_data\n",
			"\tApprovalComment = \"Approval calculation made by API\"";
		my $error_code = scw_api_reject_ticket(TicketID=> \$ticket_id, TicketData => $json_ticket_data,
			       UserID=>$user_id,
			       InformationComment=>$l_approval_data->{'Summary'}{'Approval Comment'},
			       ApprovalComment=>"Approval calculation made by API.");

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

sub scw_calc_approval_data{
	my %l_h_args = @_;
	my $l_ticket_data = $l_h_args{TicketData};
	my $l_ticket_id_ref = $l_h_args{TicketID};
	my $l_approval_step_name_ref = $l_h_args{ApprovalStepName};
	my $return_code = -1;

	my @approve_comment;

	print "DEBUG  ----> (scw_calc_approval_data) ----> Entering procedure with variables.\n" if $debug eq 255;

	#Getting JSON data to construct XML structure
	my @l_ticket = $l_ticket_data->{'ticket'};
	my $l_approval_step_task_data;

	my $l_approval_summary_ref;

	my $l_approval_count = 0;
	for my $step (@{$l_ticket[0]->{'steps'}{'step'}}){
		if($step->{'name'} eq $$l_approval_step_name_ref){
			if(ref($step->{'tasks'}{'task'}) eq 'ARRAY'){
				#We have more than more than one approva
				print "DEBUG  ----> (scw_calc_approval_data) ----> The data is an array with more than one approval task.\n" if $debug eq 255;
				my $l_approval_step_task_data = $step;

				#$l_approval_step_task_data = $step->{'tasks'}{'task'};
				$l_approval_summary_ref->{'Summary'}{'Approved'} = "";
				$l_approval_summary_ref->{'Summary'}{'Approval Comment'} = "";
				$l_approval_summary_ref->{'Summary'}{'Comment'} = "";
				$l_approval_summary_ref->{'Summary'}{'Pre-required-rejected'} = 0;

				for my $task (@{$step->{'tasks'}{'task'}}){
					my $l_access_approved = 0;
					my $l_access_relevant = 0;
					my $l_access_pre_requisite = 0;
					my $l_task_name = $task->{'name'};
					my $l_approver = $task->{'assignee'};
					my $l_approver_email = scw_api_search_user_email(\$l_approver);
					my $l_approver_comment;

					$l_approval_summary_ref->{'Approvals'}[$l_approval_count]{'TaskName'} = $task->{'name'};

					for my $fields ($task->{'fields'}{'field'}){
						foreach my $field (@$fields){
							if ($field->{'name'} eq "Access approved") {
								$l_approval_summary_ref->{'Approvals'}[$l_approval_count]{'Approved'} = $field->{'selection'};
							}
							elsif($field->{'name'} eq "Access is a pre-requisite for other access"){
								$l_approval_summary_ref->{'Approvals'}[$l_approval_count]{'Pre-requisite'} = $field->{'selection'};
							}
							elsif($field->{'name'} eq "Access is relevant"){
								$l_approval_summary_ref->{'Approvals'}[$l_approval_count]{'Relevant'} = $field->{'selection'};
							}
							elsif($field->{'name'} eq "Approval comment"){
								$l_approval_summary_ref->{'Approvals'}[$l_approval_count]{'Comment'} = $field->{'text'};
								$l_approver_comment = $field->{'text'};
							}
						}
					}

					if ($l_approval_summary_ref->{'Approvals'}[$l_approval_count]{'Approved'} eq "Yes") {
						print __LINE__ .  ":Assigning access approval data  :";
						$l_access_approved = 1;
						print __LINE__ .  ":Value set : $l_access_approved.\n";
					}
					if($l_approval_summary_ref->{'Approvals'}[$l_approval_count]{'Pre-requisite'} eq "Yes"){
						$l_access_pre_requisite = 1;
					}
					if($l_approval_summary_ref->{'Approvals'}[$l_approval_count]{'Relevant'} eq "Yes"){
						$l_access_relevant = 1;
					}

					print __LINE__ .  ":Variables  : \n approved : $l_access_approved \n Pre-requisite : $l_access_pre_requisite \n Relevant : $l_access_relevant\n";

					if ($l_access_approved and $l_access_pre_requisite and $l_access_relevant) {
						#We have a relevant, approved and required access
						print __LINE__ . "Calculating value for approved, relevant and required access for task : " . $l_task_name ."\n";

						$l_approval_summary_ref->{'Summary'}{'Approved'} = 1;
						$l_approval_summary_ref->{'Summary'}{'Pre-requisite'} = 1;
						$l_approval_summary_ref->{'Summary'}{'Relevant'} = 1;
					}
					elsif($l_access_approved and ($l_access_pre_requisite eq 0) and ($l_access_relevant eq 0)){
						print __LINE__ . ":Calculating value for approved and relevant not required access for task : " . $l_task_name ."\n";

						if ($l_approval_summary_ref->{'Summary'}{'Pre-required-rejected'} eq 0) {
							$l_approval_summary_ref->{'Summary'}{'Approved'} = 1;
						}
					}
					elsif(($l_access_approved eq 0) and ($l_access_pre_requisite)){
						#We have a rejected pre-required access
						print __LINE__ . ":Calculating value for non approved and required access for task : " . $l_task_name ."\n";

						if ($l_approval_summary_ref->{'Summary'}{'Pre-required-rejected'} eq 0) {
							$l_approval_summary_ref->{'Summary'}{'Pre-required-rejected'} = 1;
							$l_approval_summary_ref->{'Summary'}{'Pre-requisite'} = 1;
							$l_approval_summary_ref->{'Summary'}{'Approved'} = 0;
						}
					}
					elsif($l_access_approved and ($l_access_pre_requisite eq 0) and $l_access_relevant){
						#We have a relevant access eventually not approved
						print __LINE__ .  ":Calculating value for non relevant, approved and required access: for task : " . $l_task_name ."\n";

						if ($l_approval_summary_ref->{'Summary'}{'Pre-required-rejected'} eq 0) {
							$l_approval_summary_ref->{'Summary'}{'Approved'} = 1;
						}
						$l_approval_summary_ref->{'Summary'}{'Relevant'} = 1;

					}
					elsif(($l_access_approved eq 0) and ($l_access_relevant eq 0) and ($l_access_pre_requisite eq 0)){
						print __LINE__ .  ":Calculating value for non relevant, approved and required access:\n";
						if ($l_approval_summary_ref->{'Summary'}{'Pre-required-rejected'} eq 1) {
							$l_approval_summary_ref->{'Summary'}{'Approved'} = 0;
						}
					}
					else{
						#Access is rejected by default.
						$l_approval_summary_ref->{'Summary'}{'Approved'} = 0;
					}
					print __LINE__ .  ":Approval status : " . $l_approval_summary_ref->{'Summary'}{'Approved'} . "\n";
					$l_approval_summary_ref->{'Summary'}{'Approval Comment'} .= "Task Name \t: $l_task_name \n";
					$l_approval_summary_ref->{'Summary'}{'Approval Comment'} .= "\t Approver \t: $l_approver\n";
					$l_approval_summary_ref->{'Summary'}{'Approval Comment'} .= "\t Approver email : $l_approver_email\n",
					$l_approval_summary_ref->{'Summary'}{'Approval Comment'} .= "\t Required \t: $l_access_pre_requisite\n";
					$l_approval_summary_ref->{'Summary'}{'Approval Comment'} .= "\t Approved \t: $l_access_approved\n";
					$l_approval_summary_ref->{'Summary'}{'Approval Comment'} .= "\t Relevant \t: $l_access_relevant\n";
					$l_approval_summary_ref->{'Summary'}{'Approval Comment'} .= "\t Comment \t: $l_approver_comment\n";

					$l_approval_count++;
					print __LINE__ .  ":Data Dumper l_approval_summary : " . Dumper($l_approval_summary_ref);

				}
			}
			else{
				#We have one approval.
				print "DEBUG  ----> (scw_calc_approval_data) ----> The data is an array with a single approval task.\n" if $debug eq 255;
				push @{$l_approval_step_task_data},$step;
			}



			if ($l_approval_summary_ref->{'Summary'}{'Pre-required-rejected'} eq 1) {
				#The access is rejected
				$return_code = 0;
			}
			else{
				#The access is accepted and some tasks may be deleted
				$return_code = 1;
				return $return_code,$l_approval_summary_ref;
			}



		}
        }

	return ($return_code,$l_approval_step_task_data);
}

sub scw_api_approve_ticket{
	#Procedure executed to approve a ticket by the API.
	# Approval XML to send.
	# URL : https://scw_IP/securechangeworkflow/api/securechange/tickets/<ticket_ID>/steps/current/tasks/<task_ID>
	#<task>
	#  <id>623</id>
	#  <assignee_id>24</assignee_id>
	#  <status>DONE</status>
	#  <fields>
	#    <field xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="text_area">
	#      <id>18994</id>
	#      <name>Information about AR modification</name>
	#      <read_only>false</read_only>
	#      <text>This is the approval summary for the request</text>
	#    </field>
	#    <field xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="approve_reject">
	#      <id>18995</id>
	#      <name>Approval summary</name>
	#      <approved>true</approved>
	#      <reason>Not all relevant firewalls and requests were approved.</reason>
	#      <reason />
	#    </field>
	#  </fields>
	#</task>

	my %l_h_args = @_;
	my $l_ticket_data = $l_h_args{TicketData};
	my $l_user_id 	= $l_h_args{UserID};
	my $l_ticket_id = $l_h_args{TicketID};
	my $l_approval_comment = $l_h_args{ApprovalComment};
	my $l_information_comment = $l_h_args{InformationComment};
	my $l_information_field_name = "";
	my $l_information_field_id = 0;

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
				elsif($field->{'@xsi.type'} eq 'text_area'){
					$l_information_field_name = $field->{'name'};
					$l_information_field_id = $field->{'id'};
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

		# Specific Information text area field
		my $o_field_information= XML::LibXML::Element->new('field');
		$o_field_information->setAttribute('xmlns:xsi' => "http://www.w3.org/2001/XMLSchema-instance");
		$o_field_information->setAttribute('xsi:type' => "text_area");
		$o_fields_list->addChild($o_field_information);

		my $o_field_information_id = XML::LibXML::Element->new('id');
		$o_field_information_id->appendText($l_information_field_id);
		$o_field_information->addChild($o_field_information_id);

		my $o_field_information_name = XML::LibXML::Element->new('name');
		$o_field_information_name->appendText($l_information_field_name);
		$o_field_information->addChild($o_field_information_name);

		my $o_field_information_text = XML::LibXML::Element->new('text');
		$o_field_information_text->appendText($l_information_comment);
		$o_field_information->addChild($o_field_information_text);

		# Approval field
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
			print "ERROR ----> scw_api_approve_ticket " . __LINE__ ,
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


sub scw_api_reject_ticket{
	my %l_h_args 	= @_;
	my $l_ticket_data = $l_h_args{TicketData};
	my $l_user_id 	= $l_h_args{UserID};
	my $l_information_comment = $l_h_args{InformationComment};
	my $l_reject_comment = $l_h_args{ApprovalComment};
	my $l_ticket_id = $l_h_args{TicketID};
	my $return_code = -1;

	#<task>
	#  <id>623</id>
	#  <assignee_id>24</assignee_id>
	#  <status>DONE</status>
	#  <fields>
	#    <field xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="text_area">
	#      <id>18994</id>
	#      <name>Information about AR modification</name>
	#      <read_only>false</read_only>
	#      <text>This is the approval summary for the request</text>
	#    </field>
	#    <field xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="approve_reject">
	#      <id>18995</id>
	#      <name>Approval summary</name>
	#      <approved>false</approved>
	#      <reason>Not all relevant firewalls and requests were approved.</reason>
	#      <reason />
	#    </field>
	#  </fields>
	#</task>

	#Getting JSON data to construct XML structure

	my @l_ticket = $l_ticket_data->{'ticket'};
	my $l_ticket_current_step = $l_ticket[0]->{'current_step'}{'id'};
	my $l_task_id = 0;
	my $l_approve_field_id = 0;
	my $l_approve_field_name = "";
	my $l_information_field_name = "";
	my $l_information_field_id = 0;

	for my $step (@{$l_ticket[0]->{'steps'}{'step'}}){
                if ($step->{'id'} eq $l_ticket_current_step) {
                        $l_task_id = $step->{'tasks'}{'task'}{'id'};
			for my $field (@{$step->{'tasks'}{'task'}{'fields'}{'field'}}){
				if ($field->{'@xsi.type'} eq 'approve_reject') {
					$l_approve_field_id = $field->{'id'};
					$l_approve_field_name = $field->{'name'};
				}
				elsif($field->{'@xsi.type'} eq 'text_area'){
					$l_information_field_name = $field->{'name'};
					$l_information_field_id = $field->{'id'};
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

		# Specific Information text field
		my $o_field_information = XML::LibXML::Element->new('field');
		$o_field_information->setAttribute('xmlns:xsi' => "http://www.w3.org/2001/XMLSchema-instance");
		$o_field_information->setAttribute('xsi:type' => "text_area");
		$o_fields_list->addChild($o_field_information);

		my $o_field_information_id = XML::LibXML::Element->new('id');
		$o_field_information_id->appendText($l_information_field_id);
		$o_field_information->addChild($o_field_information_id);

		my $o_field_information_name = XML::LibXML::Element->new('name');
		$o_field_information_name->appendText($l_information_field_name);
		$o_field_information->addChild($o_field_information_name);

		my $o_field_information_text = XML::LibXML::Element->new('text');
		$o_field_information_text->appendText($l_information_comment);
		$o_field_information->addChild($o_field_information_text);

		# Approval field
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
		$o_field_approve_reason->appendText($l_reject_comment);
		$o_field_approve->addChild($o_field_approve_reason);

		my $o_field_approve_status = XML::LibXML::Element->new('approved');
		$o_field_approve_status->appendText('false');
		$o_field_approve->addChild($o_field_approve_status);

		my $xml_string = $o_new_dom->toString;

		my $url = "/securechangeworkflow/api/securechange/tickets/$$l_ticket_id/steps/current/tasks/$l_task_id";
		$sc_client->PUT($url, $xml_string);
		if ($sc_client->responseCode() ne "200") {
			print "ERROR ----> scw_api_approve_ticket " . __LINE__ ,
				"----> Error during API call while approving the ticket step : " . $sc_client->responseCode(),
				"\n";
			exit 1;
		}
		return 1;
	}
	else{
		return -1;
	}
}

sub scw_api_reassign_ticket{
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

sub scw_api_search_user_id{
	#Procedure to get a user ID in SecureChange for ticket reassignment
	my $rl_user_name = shift;
	my $url = "/securechangeworkflow/api/securechange/users.json";
	$sc_client->GET($url);
	if ($sc_client->responseCode() ne "200") {
		print "ERROR ----> scw_api_search_user_id " . __LINE__ ,
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


sub scw_api_validate_current_step{
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

sub scw_api_get_ticket_data{
	my $r_ticket_id = shift;
	my $url = "/securechangeworkflow/api/securechange/tickets/$$r_ticket_id.json";
	$sc_client->GET($url);
	if ($sc_client->responseCode() ne "200") {
		print "ERROR ----> scw_api_get_ticket_data " . __LINE__ ,
			"----> Error during API call while retrieving ticket data with error Code : " . $sc_client->responseCode(),
			"\n";
		exit 1;
	}
	my $jsonticket = decode_json($sc_client->responseContent());
	return ($jsonticket);
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

sub scw_api_search_user_email{
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
			if(defined($userdata->{'email'})){
				return $userdata->{'email'};
			}
			else{
				return "Unknown email address";
			}
		}
	}
	return -1;
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
