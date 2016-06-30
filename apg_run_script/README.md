Perl Scripts
============

The following sample scripts demonstrate the interaction between the Tufin infrastructure and the Tufin API in order to enhance the capabilities of the Tufin Security Suite.
These scripts are provided as sample code for the functionality without any warranty.

Installation Instructions
-------------------------
The libraries archive contain the required RPM packages that needs to be installed into the solution.

On the Tufin Central Server:
 - follow the instructions to install the perl libraries
 - copy this script to the same directory as the perl libraries
 - execute the script with the appropriate parameters (see below)

Example:  /usr/bin/perl ./apg_run_script.pl [parameters]

Usage:
apg_run_script.pl -device-name <management name>
	[-policy-package <Name of the policy package>]
	-rule-list <list of rule numbers>
	-duration <number of days for analysis>
	[-debug ] [-help]
	Parameters details:
	rule-list : The list of rules on which the user wish to run APG on in the form
	Accepted forms : 1,2-4
	[-help]

Help
----
Tufin Technical Support will be able to help on some of the functionality related to the API, but will will not assist on the script usage or changes.