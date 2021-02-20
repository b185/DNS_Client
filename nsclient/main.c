#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Header.h"
#include "winsock2.h"


int main(int argc, char *argv[]) {
	int flag = 1; 
	unsigned short  id = 0x0000;
	HOSTENT *output;
	
	if ((argc != 2) || (argv[1] == NULL)) {
		printf("The correct number of arguments were not inserted :: Please exit and re-enter\n ");
		return 1; }


	//IP will be inserted as args
	char *IP = argv[1];
	
	//Domains will be inserted after entering main loop
	char *domain_name = NULL; 
	free(domain_name);
	///DNS server IP address validity check
	if (check_ip_address(IP) == IP_ADDRESS_IS_INVALID) { 
		printf("Error: Bad Server IP\n");
		return 1; }

	domain_name = (char*)malloc(sizeof(char)*NAME_LENGTH);
	while ((flag) && (id < 65536)) {
		

		printf("nsclient> "); 
		///Scan screen for Domain name input
		scanf("%s", domain_name);



		///Domain name validity check
		switch (check_domain_name(domain_name)) {
		case QUIT_WAS_INSERTED:
			flag = 0; break;
		case DOMAIN_NAME_IS_INVALID:
			printf("Error: Bad Domain Name :: Enter a new domain name\n");
			break;
		case DOMAIN_NAME_IS_VALID:
			output = dnsQuery(IP, domain_name, id);
			if (output != NULL) 
				print_output_to_the_screen(output);
			id++; break;
		}
	}

	///Domain name memory release
	free(domain_name);
	return 0;
}