Perl Scripts
============

The following sample scripts demonstrate the interaction between the Tufin infrastructure and the Tufin API in order to enhance the capabilities of the Tufin Orchestration Suite.
These scripts are provided as sample code for the functionality without any warranty.


Purpose
-------

This script will take a step with multiple approvals in various fields and calculate the resulting approval of the ticket prior the change is being executed by the operation teams.


Installation Instructions
-------------------------
The libraries archive contain the required RPM packages that needs to be installed into the solution.

On the Tufin SecureChange Central Server:
 1. have the perl libraries installed
 2. Create a new step named "Subticket-approval" in a workflow with the following informations:
    - Fields:v
	- AR Field        : Access Request
        - Drop down field : Access is relevant
        - Drop down field : Access is a pre-requisite for other access
        - Drop down field : Access Approved
	- Text Area       : Approval comment
    - Assign the step to the relevant users using either scripted assignemnt or with dynamic assignment
 3. Add a step after "Subticket-approval" named "Verify all approvals"
    - Fields:
        - AR Field      : Access Request
        - Text Area     : Information about AR modifications
        - Approval      : Approval summary
    - Assign the step to the API user
 4. In the SecureChange Settings / API add an API trigger under create / advance and use the script as a parameter
 5. Edit the /opt/tufin/securitysuite/ps/api.conf file
    - add the following section

        [validate-approvals]
        step = "Verify all approvals"
        users-approval-step = "Subticket Approval"


Help
----
Tufin Technical Support will be able to help on some of the functionality related to the API, but will will not assist on the script usage or changes.