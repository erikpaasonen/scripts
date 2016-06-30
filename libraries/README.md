Perl Libraries
==============

The libraries are providing the minimum perl elements that will be used for the sample script to run and be executed.
The following sample scripts demonstrate the interaction between the Tufin infrastructure and the Tufin API in order to enhance the capabilities of the Tufin Security Suite.
These scripts are provided as sample code for the functionality without any warranty.


Installation Instructions
-------------------------
The libraries archive contain the required RPM packages that needs to be installed into the solution.

On the Tufin Central Server:
 - mkdir /opt/tufin/securitysuite/ps/perl
 - copy the libraries files into /opt/tufin/securitysuite/ps/perl directory
 - cd /opt/tufin/securitysuite/ps/perl
 - unzip libraries
 - rpm -ivh ./required-rpms/*
 - vi api.cfg and set the relevant IP addresses and user parameters
 - chown tomcat:apache -R /opt	/tufin/securitysuite/ps/perl


Scripts available
-----------------
 - apg_run_script can be used to generate multiple APG jobs for a given firewalls
 - assign_approver_from_app can be used to trigger specific approval for some SecureApp applications during a change process


Help
----
Tufin Technical Support will be able to help on some of the functionality related to the API, but will will not assist on the script usage or changes.
