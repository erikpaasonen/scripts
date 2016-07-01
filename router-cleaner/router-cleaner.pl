#!/usr/bin/perl
# TODO : Check if target not equals ANY
use lib '../extlib/lib/perl5';
use lib './extlib/lib/perl5';
use lib '/opt/tufin/securitysuite/ps/perl/extlib/lib/perl5';
use strict;
use warnings;
# Standard libs
use MIME::Base64;
use REST::Client;
use JSON;
use Storable 'dclone';
use Config::Simple;
# For debugging only
use Data::Dumper;
$Data::Dumper::Indent = 1;

# Makemaker Variables
our $VERSION = '1.0';
our $RELEASE_DATE = '2016-01-13';

# Read Ticket information for STDIN
my $xml = '';
while (<STDIN>) {
	$xml .= $_;
}
my $ticket_id = 0;
$xml =~ m/<ticket_info><id>(\d+)<\/id>/;
$ticket_id = $1;

# Specific condition when Test button is pushed from GUI
if (not defined $ticket_id || $ticket_id eq 'test') {
  	print "<response><condition_result>true</condition_result></response>\n";
	exit 0;
}

# Retrieving data from configuration file
my $cfg = new Config::Simple('/opt/tufin/securitysuite/ps/perl/api.cfg');

my $st_host = $cfg->param("securetrack.host");
my $st_user = $cfg->param("securetrack.user");
my $st_pass = $cfg->param("securetrack.pass");

my $sc_host = $cfg->param("securechange.host");
my $sc_user = $cfg->param("securechange.user");
my $sc_pass = $cfg->param("securechange.pass");

# SSL verification
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = $cfg->param("ssl.certificate-check");
my $step_name = $cfg->param("routercleaner.step");

# Prepare Rest::Client for SecureTrack
my $st_client = REST::Client->new(host => $st_host);
my $st_encoded_auth = encode_base64("$st_user:$sc_pass", '');
$st_client->addHeader( "Authorization", "Basic $st_encoded_auth");
$st_client->addHeader( "Accept", "application/json" );

# Prepare Rest::Client for SecureChange
my $sc_client = REST::Client->new(host => $sc_host);
my $sc_encoded_auth = encode_base64("$sc_user:$sc_pass", '');
$sc_client->addHeader( "Authorization", "Basic $sc_encoded_auth");
$sc_client->addHeader( "Accept", "application/json" );


# Retrieve ticket information
my $ticket = get_ticket($ticket_id);
exit 0 if ($ticket->{ticket}->{current_step}->{name} ne $step_name);

my $current_step_id = $ticket->{ticket}->{current_step}->{id};
my $current_task_id = get_current_task_id($ticket);
# ID Field AR in current step
my $current_field_id = get_current_field_id($ticket);

# Catch ARs from previous step
my $access_requests = get_field_access_requests($ticket);
# Demux & Clean Access Requests
my $new_access_requests = clean_access_requests($access_requests);

# Update Ticket
update_ars($ticket_id, $current_step_id , $current_task_id, $current_field_id, $new_access_requests);

# Go to the next step
update_task($ticket_id, $current_task_id);

print "<response><condition_result>true</condition_result></response>\n";

###############################################################################
#
# LOGIC
#
###############################################################################
sub load_regions {
	my $regions_file = shift;
	my $hregions;

	open (regions_file, "<$regions_file") or die "can't read file $regions_file.\n";
	while (<regions_file>) {
		chomp;
		my ($fw, $region) = split /;/, $_;
		$hregions->{$fw} = $region;
	}
	close (regions_file);
	return $hregions;
}

# Main Logic
sub clean_access_requests {
	my $field = shift;
	my $new_field;

	# Copy references for old field
	#$new_field->{field}->{id} = $field->{id};
	$new_field->{field}->{name} = $field->{name};
	$new_field->{field}->{'@xsi.type'} = $field->{'@xsi.type'};
	

	### Check type ARRAY or SINGLE ELEM
	my $ars;
	if(ref($field->{access_request}) eq 'ARRAY'){
		$ars = $field->{access_request};
	}
	else {
		push @$ars, $field->{access_request};
	}
	###

	# Foreach AR
	foreach my $ar (@$ars) {
		# 1 - Prepare a clone of informations
		my $new_ar = dclone $ar;
		delete $new_ar->{id};
		delete $new_ar->{order};
			
		### Check type ARRAY or SINGLE ELEM
		my $new_targets;
		if(ref($new_ar->{targets}->{target}) eq 'ARRAY'){
			$new_targets = $new_ar->{targets}->{target};
		}
		else {
			push @$new_targets, $new_ar->{targets}->{target};
		}
		###
	
		# 2 - Clean targets
		for (my $i = $#{$new_targets}; $i > -1; $i--) {
			# Delete target if not it's a router
			if (get_device_type($new_targets->[$i]->{management_id}) eq 'router') {
				splice @$new_targets, $i, 1;
			}
		}

		push (@{$new_field->{field}->{access_request}}, $new_ar);
	}
	return $new_field;
}

sub get_current_task_id {
	my $ticket = shift;
	die "Can't get current_step for ticket $ticket->{ticket}->{id}\n" if !$ticket->{ticket}->{current_step};
	my $current_step = $ticket->{ticket}->{current_step}->{id};
	# Get the previous step
	foreach my $step (@{$ticket->{ticket}->{steps}->{step}}) {
		if ($step->{id} == $current_step) {
			return $step->{tasks}->{task}->{id};
		}
	}
}

sub get_current_field_id {
	my $ticket = shift;
	die "Can't get current_step for ticket $ticket->{ticket}->{id}\n" if !$ticket->{ticket}->{current_step};
	my $current_step = $ticket->{ticket}->{current_step}->{id};

	# Get the previous step
	foreach my $step (@{$ticket->{ticket}->{steps}->{step}}) {
		if ($step->{id} == $current_step) {
			my $fields;
			if(ref($step->{tasks}->{task}->{fields}->{field}) eq 'ARRAY'){
				$fields = $step->{tasks}->{task}->{fields}->{field};
			}
			else {
				push @$fields, $step->{tasks}->{task}->{fields}->{field};
			}
			foreach my $field (@$fields) {
				if ($field->{'@xsi.type'} eq 'multi_access_request') {
					return $field->{id};
				}
			}	
		}
	}
}

sub get_field_access_requests {
	my $ticket = shift;
	die "Can't get current_step for ticket $ticket->{ticket}->{id}\n" if !$ticket->{ticket}->{current_step};
	my $current_step = $ticket->{ticket}->{current_step}->{id};
	my $previous_step = $current_step - 1;
	# Get the previous step
	foreach my $step (@{$ticket->{ticket}->{steps}->{step}}) {
		if ($step->{id} == $previous_step) {
			my $fields;
			if(ref($step->{tasks}->{task}->{fields}->{field}) eq 'ARRAY'){
				$fields = $step->{tasks}->{task}->{fields}->{field};
			}
			else {
				push @$fields, $step->{tasks}->{task}->{fields}->{field};
			}
			foreach my $field (@$fields) {
				if ($field->{'@xsi.type'} eq 'multi_access_request') {
					return $field;
				}
			}	
		}
	}
}

###############################################################################
#
# API HELPERS
#
###############################################################################
sub update_ars {
	my ($ticket_id, $step_id, $task_id, $field_id, $field) = @_;
	
	$sc_client->addHeader('Content-Type', 'application/json');
	print "PUT /securechangeworkflow/api/securechange/tickets/$ticket_id/steps/$step_id/tasks/$task_id/fields/$field_id\n\n".JSON->new->pretty->encode($field)."\n\n\n\n";
	$sc_client->PUT("/securechangeworkflow/api/securechange/tickets/$ticket_id/steps/$step_id/tasks/$task_id/fields/$field_id", to_json($field));
	
	return 1 if $sc_client->responseCode() eq '200';
	$sc_client->responseContent() =~ m/.+<message>(.+)<\/message>/;
	print "\tError, can't update_ticket :\n";
	print $sc_client->responseContent()."\n";
	return 0;
}

sub update_task {
	my ($ticket_id, $task_id) = @_;
	my $task;

	$task->{task}->{id} = $task_id;
	$task->{task}->{status} = 'DONE';
	$task->{task}->{fields} = { };
	
	print "PUT /securechangeworkflow/api/securechange/tickets/$ticket_id/steps/current/tasks/$task_id\n\n".JSON->new->pretty->encode($task)."\n\n\n\n";
	$sc_client->addHeader('Content-Type', 'application/json');
	$sc_client->PUT("/securechangeworkflow/api/securechange/tickets/$ticket_id/steps/current/tasks/$task_id", to_json($task));
	
	return 1 if $sc_client->responseCode() eq '200';
	$sc_client->responseContent() =~ m/.+<message>(.+)<\/message>/;
	print "\tError, can't update_ticket :\n";
	print $sc_client->responseContent()."\n";
	return 0;
	
}

sub get_ticket {
	my $ticket_id = shift;
	
	$sc_client->GET("/securechangeworkflow/api/securechange/tickets/$ticket_id");
	die "Bad Response from get_ticket : ".$sc_client->responseContent() if $sc_client->responseCode() ne "200";
	return (decode_json($sc_client->responseContent()));
}

sub get_device_type {
	my $device_id = shift;

	$st_client->GET("/securetrack/api/devices/$device_id");
	die "Bad Response from get_device_type" if $st_client->responseCode() ne "200";
	my $obj = decode_json($st_client->responseContent());
	return $obj->{device}->{model};
}

