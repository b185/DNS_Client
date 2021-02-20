# DNS_Client
Introduction to Computer Communications course at Tel-Aviv University Exercise 1 - "Streamlined nslookup"


This is a C programming language application compiled in Windows environment with the Microsoft Visual Studios 2017 x86 compiler. 
This application is an implementation of DNS client, which behaves as a streamlined version of the DNS query function "nslookup"(2-directions-translation). This client can only to query the DNS server for IP addresses some input Domain name (single direction), which is expressed by the following chain:

                   client   ----->         domain name      ----->  DNS server
                      
                   client   <-----   matching IP addresses  <-----  DNS server
                      

It communicates with the local DNS server by sending connectionless DNS query datagrams as part of the UDP communication scheme with the RFC 1035 messaging format.
At the beginning of every query sent from the client, a string of non-blank characters - Domain Name - is received from the user(client). 
Then, the application listens for the DNS response from the DNS local server, which will be a set of matching IP addresses associated with the sent Domain Name.

The communication between the client and the DNS server is handled with socket programming by utilizing various functions of the Winsock library.

The input to the program will be the DNS server IP address, and will interact with the user the entire duration of the program's runtime.



Notes:

  1) Different messages may be outputted when various malfunctions occur  


Testing:

  1) Initiate the program with you local DNS server IP address as input (such can be retrieved by using ipconfig /all in CMD console)
  2) Enter a Domain name...
  3) Type "quit" in order to terminate
