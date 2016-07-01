Perl Scripts
============

The following sample scripts demonstrate the interaction between the Tufin infrastructure and the Tufin API in order to enhance the capabilities of the Tufin Orchestration Suite.
These scripts are provided as sample code for the functionality without any warranty.

Installation Instructions
-------------------------
The libraries archive contain the required RPM packages that needs to be installed into the solution.

On the Tufin Central Server:
 1. have the perl libraries installed
 2. in the Application that needs validation
 3. enter in the application comment a XML string in the form
	<Custom>
	<Branch>ABC</Branch>
	<pre-validation-group>Validation Group</pre-validation-group>
	</Custom>
 4. Create a new step named "Pre-approval" in a workflow with the following informations:
    - Fields:
	- Access Request
	- Approve Reject
    - Assign the step to the API user with Auto Assignment
 5. In the SecureChange Settings / API add an API trigger under create / advance and use the script as a parameter
 6. Edit the /opt/tufin/securitysuite/ps/api.conf file
    - add the following section

	[assign_validation_from_app]
	steps="Pre-approval"
 7. Add a role named "Application approvers Role" with the following roles:
    - View Tasks
    - Reject Tickets
    - View tasks assigned to other users
 8. Add a validation group named 'Validation Group"
    - Add and assign the relevant users to it.
    - Set permission to "Member of this group can handle other members tasks"
    - Set role to "Application approvers Role"


Help
----
Tufin Technical Support will be able to help on some of the functionality related to the API, but will will not assist on the script usage or changes.