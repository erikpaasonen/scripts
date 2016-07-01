Perl Scripts
============

The following sample scripts demonstrate the interaction between the Tufin infrastructure and the Tufin API in order to enhance the capabilities of the Tufin Orchestration Suite.
These scripts are provided as sample code for the functionality without any warranty.


Purpose
-------

This script will take all Access Requests from a SecureChange ticket and remove the routers from the each AR and only keep the firewalls.

Installation Instructions
-------------------------
The libraries archive contain the required RPM packages that needs to be installed into the solution.

On the Tufin Central Server:
 1. have the perl libraries installed
 3. Create a new step named "remove-routers" in a workflow with the following informations:
    - Fields:
	- Access Request
    - Assign the step to the API user with Auto Assignment
 4. In the SecureChange Settings / API add an API trigger under create / advance and use the script as a parameter
 5. Edit the /opt/tufin/securitysuite/ps/api.conf file
    - add the following section

	[routercleaner]
	step="remove-routers"


Help
----
Tufin Technical Support will be able to help on some of the functionality related to the API, but will will not assist on the script usage or changes.