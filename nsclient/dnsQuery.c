#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Header.h"

#include <winsock2.h>



HOSTENT* dnsQuery(char *ip_address, char *domain_name, unsigned short id){// dnsQuery(){//(char *domain_name ,char *ip_address) { return type = HOSTENT*

	///Variables Declerations & Partial memory allocations
	fd_set *set = NULL;
	HOSTENT *output = NULL;
	QueryRFC1035 *msg_out = NULL; 
	AnswerRFC1035 *msg_in = NULL;
	char *response_memory = NULL; /// response_memory will hold behave as the buffer to the incoming reponse
	int flag = 0, no_of_answers = -2; /// flag would indicate whether dnsQuery was successful or not
	

	
	///Winsock DLLs initialization ->maybe transfer to function that returns nothing (void)
	WSADATA wsaData; // Here we make sure the winsock DLL is opened correctly
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
		printf("Error at WSAStartup() No. %d\n", WSAGetLastError());
		return 0; }

	///Socket Boot
	SOCKET s = socket(PF_INET /*PF_INET for protocol*/, SOCK_DGRAM, 0 /*IPPROTO_UDP*/); //IPPROTO_UDP is used for the self-tests before constructing PA1's protocol
	if (s == INVALID_SOCKET) {//REMOVE later
		printf("socket failed with error : %d\n", WSAGetLastError());
		return 0; }
		
	///Inserting socket into Socket set -> perhaps i should use FD_SET(s,set);
	set = (fd_set*)malloc(sizeof(fd_set));
	FD_ZERO(set);
	FD_SET(s, set);


		
		





	///Preparing message data for sending, in QueryRFC1035 struct
	msg_out = construct_message_for_sending(domain_name,id);
	///Sending data using the socket allocated through a port to the DNS server IP address
	if (send_function(s, msg_out, ip_address, strlen(domain_name) + 2 + 16) == MESSAGE_WAS_SENT) {
		///Using socket
		if (identify_whether_data_has_returned(set) == RECIEVE_MESSAGE_WILL_SUCCEED) {
			response_memory = (char*)malloc(sizeof(char) * MAX_MESSAGE_SIZE /*sizeof(*msg)*/);///NOTE
			if (receive_function(s, ip_address, response_memory) == PROCEED_TO_ANALYZE_MESSAGE) {
				msg_in = (AnswerRFC1035*)malloc(sizeof(AnswerRFC1035));
				no_of_answers = response_parsing_and_answer_construction(msg_in, response_memory, msg_out, strlen(domain_name) + 2 /*size of domain_name*/);
				if (no_of_answers != NO_DATA_RESPONSE) {
					output = (HOSTENT*)malloc(sizeof(HOSTENT));
					construct_hostent(output, msg_in, no_of_answers);  //(when i used of RESREC **answers)Here i may also update AnswerRFC1035 *msg_in to have a single answer for future assignments......
					flag = 1;
				} //PROCCEED TO PRINT SEND HOSTENT  
				else
					free(msg_in);
			}
			else
				free(response_memory);
		}
	}

	
	


	

	//Memory Evacuation - fd_set structure & messages structures
	free_function_1D(set, msg_out); 
	
	
	
	



	//Socket Closure
	if (shutdown(s, SD_BOTH) != 0) {
		//printf("Socket shutdown was successful\n"); //add else with WSAGETLASTERROR()
		printf("Socket shutdown failed with error %d\n", WSAGetLastError());
		if (no_of_answers >-1)
			free(output);
		return NULL; }
	if (closesocket(s) != 0) {
		//printf("Socket shutdown and closure was successful\n");
		printf("Socket closure failed with error %d\n", WSAGetLastError());
		if (no_of_answers > -1)
			free(output);
		return NULL; }

	//Winsock DLLs shutdown
	if (WSACleanup() == SOCKET_ERROR) {
		printf("WSACleanup failed with error %d\n", WSAGetLastError());
		if (no_of_answers > -1)
			free(output);
		return NULL; }

	
	


	
	///flag == 1 -> At least one answer was retrieved,  flag == 0 -> We received no answers 
	if (flag)
		return output; 
	else
		return NULL;
}

