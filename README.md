Implementing a Secure-Audit-Log-System
======================================
Using OpenSSL and C, make a secure audit log system


Author: Anantha Raghuraman
--------------------------

# Goal of the Project

1) Build a secure audit-log system as per the protocol mentioned in Secure Audit Logs to Support Computer Forensics by Bruce Schneier and John Kelsey.

2) Assume the existence of a trusted server and build a secure audit log system on an untrusted computer.

3) The log file will contain information about creation of a log file, adding entries to the log file and closing the log file.

4) The entries in the log file will be such that they can be decoded only by the trusted server at any points of time.

5) Make provision for a "Verifier" that can make secure connections with the trusted server and untrusted computer and verify the entries of the log file and check that they are correct.

6) All the protocols for handling the log file and communication was followed exactly as mentioned in the Secure Audit Logs to Support Computer Forensics by Bruce Schneier and John Kelsey


# Commands that are supported by the shell

1) newlog: Create a new log
	Arguments: It takes one argument, the name of the new file to be created. 
	Action: As soon as the file is created, an entry is made indicating that the logfile was created. If file could not be created, then a log entry is created indicating this. If already a logfile is open, close that and then open this.

2) append: Append an entry to currently open log
	Arguments: It takes one argument, the string that should be appended to the log file.
	Action: This adds an entry to the log file after processing the string input. Print an error if no logfile is open. 

3) verify_entry: It verifies that a particular entry in the currently open log file is correct. 
	Arguments: Entry number (an integer).
	Action: This is mostly performed by the verifier. It checks that a particular entry is a valid entry (i.e. it has not been tampered). Throw an error if it is not. Or, print that the entry is correct. Print an error if no logfile is open.

4) verify_log: It verifies the entrie log file that is currently open.
	Arguments: NIL
	Action: This is mostly done by the verifier. Go through all the entries in the log file and verify that they are right. Throw an error if it is not. Or print that they are correct. Print an error if no logfile is open. 

5) closelog: Closes the currently open log file
	Arguments: NIL
	Action: Close the log file if one is open now. Else, throw an error.

6) exit: Exits the shell after closing the currently open log file, if any.


# Method Synopsis

i) HASHING
	Sha_256 hash function was always used for hashing

ii) Symmetric Encryption
	AES_256 was always used. Initial vector is 0.

iii) HMAC
	For HMAC, Initial vector is 0 and SHA_256 was used as digest.

iv) Asymmetric Encryption and Digital Certificate
	RSA was always used with key size as 1024.


Files and Running Information
i) genkeys.sh: Generate all the public and private keys (of trusted server T, untrusted machine U). Also generate a self-signed certificate for U and a public-private key pair for T, for its Digital Signature.

ii) Compilation: Please check the Makefile

iii) Running command: ./main

	