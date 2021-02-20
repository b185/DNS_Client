#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Header.h"

#include <winsock2.h>



//$$$$$$$$$$$$$$$$$$$$$$$$$     main.c    Functions    $$$$$$$$$$$$$$$$$$$$$$

///Labels are defined to be a string from the start to a '.', from '.' to '.', and from '.' to end (\0)
///RULES: All character are between 0 - 255 with extra demands for DNS server IP addresses
///	      Every label's size is no greater than 63 octets. Entire domain name's size is no greater than 255 octets. ALL ELSE IS INVALID (Suitable even for DNS servers' IP address even if they are unreacable which will result in TIMEOUT error)
int check_ip_address(char* ip_address) 
{
	int i = 0, number = 0;
	char dot = '.', *section = NULL, *ip = NULL,  *to_free_ip=NULL;

	if ((*ip_address == '\0') || (strlen(ip_address)>15)) 
		return IP_ADDRESS_IS_INVALID; ///ip address is either NULL or too big

	ip = (char*)malloc(sizeof(char)*strlen(ip_address)+1);///So i don't ruin the IP address (The input is pointer to the original data)
	strcpy(ip, ip_address); /// need to create a new string because operations such as *section = '\0'; or strtok(ip_address)[not invalid but string-desstroyer]; are invalid without an additional copy
	to_free_ip = ip;

	while ((section != NULL) || (i == 0)) { ///section is NULL at the beginning and at the end of the search. Because we would like to start we use i=0 as well
		section = strchr(ip, dot); ///Fetching every label separately
		if(section != NULL)///For the case we reched the end of the string, so there won't be another '.'
			*section = '\0'; ///After finding the position of the following '.' in the address we swap it with a zero character in order to scan the number in the string
		if(check_label(ip) == LABEL_IS_INVALID)
			return IP_ADDRESS_IS_INVALID;
		sscanf(ip, "%u", &number); ///Changing a string of a number into a number  ||  sscanf will FAIL if there is any character which isn't a digit, and then label_check will receive 0
		if (number > 255) { 
			free(to_free_ip);
			return IP_ADDRESS_IS_INVALID; } ///A number that above 255 in the ip address is INVALID
		if (section != NULL) {///For the case we reched the end of the string, so there won't be another '.'
			*section = dot; ///Here we fix back the ip address to its' original state so we can keep checking the following labels of the address
			ip = section + 1; ///ip_address is a pointer living within the function so we won't lose the original address pointer outside
		}
		i++; ///Advancing i variable to check the next label in the address
	}
	free(to_free_ip);
	if (i != 4)
		return IP_ADDRESS_IS_INVALID; ///More or less than 4 sections means we have a broken ip address
	else
		return IP_ADDRESS_IS_VALID;
	
	/*int *number=(char*)malloc(sizeof(char)*8);
	strcpy(number, "12345");
	sscanf(number, "%d", &i);
	printf("\nThe value of x : %d", i);*/
}
int check_label(char *sect) ///Every label is checked to see if there are characters that are not digits
{
	while (*sect  != '\0') {
		if (check_character(sect) != CHARACTER_IS_DIGIT)
			return LABEL_IS_INVALID;
		sect++;
	}
	return LABEL_IS_VALID;
}

///Labels are defined to be a string from the start to a '.', from '.' to '.', and from '.' to end (\0)
///RULES: First character is upper or lower alphabet. Middle character is either digit, upper/lower alphabet or hyphen. Last character is upper/lower/digit.
///	      Every label's size is no greater than 63 octets. Entire domain name's size is no greater than 255 octets. ALL ELSE IS INVALID
int check_domain_name(char* domain_name)
{
	int size = 0;
	char *start = domain_name, *end = domain_name;
	if (strcmp(domain_name, "quit") == 0)
		return QUIT_WAS_INSERTED; /// "quit" was inserted and it is time to say goodbye

	if ((*domain_name == '\0') || (domain_name == NULL))
		return DOMAIN_NAME_IS_INVALID; ///NULL string OR a string that hold zero character at the beginning
	
	while (*start != '\0') {
		end = domain_name + size;

		if (end - start == 0) {
			switch (check_character(end)) { ///character at the beginning of the label
			case CHARACTER_IS_INVALID:
			case CHARACTER_IS_DIGIT:
			case CHARACTER_IS_HYPHEN:
				return DOMAIN_NAME_IS_INVALID;
			}
			if (end - start + 1 > 63)
				return DOMAIN_NAME_IS_INVALID;
			size++;
			continue;
		}
		if (*end == '.') {
			switch (check_character(end-1)) { ///character at the end of the current label
			case CHARACTER_IS_INVALID:
			case CHARACTER_IS_HYPHEN:
				return DOMAIN_NAME_IS_INVALID; }
			if (end - start > 63)
				return DOMAIN_NAME_IS_INVALID;
			start = end + 1;
			size++;
			continue;
		}
		if (*end == '\0') {
			switch (check_character(end - 1)) { ///character at the end of the current label
			case CHARACTER_IS_INVALID:
			case CHARACTER_IS_HYPHEN:
				return DOMAIN_NAME_IS_INVALID; }
			if (end - start > 63)
				return DOMAIN_NAME_IS_INVALID;
			start = end;
			size++;
			continue;
		}
		
		switch (check_character(end)) { ///character at the middle of the label
		case CHARACTER_IS_INVALID:
			return DOMAIN_NAME_IS_INVALID; }
		if (end - start + 1 > 63)
			return DOMAIN_NAME_IS_INVALID;
		size++;
	}
	size++;
	if((size>253) || (*(start - 1) == '.'))
		return DOMAIN_NAME_IS_INVALID;
	return DOMAIN_NAME_IS_VALID;//size; // CAN be changed to DOMAIN_NAME_IS_VALID instead
}
int check_character(char* character)			/// Checks whether a character is leagal or not ///
	{
	if (*character >= '0' && *character <= '9')
		return CHARACTER_IS_DIGIT;
	else if (*character >= 'A' && *character <= 'Z')
		return CHARACTER_IS_UPPER_CASE;
	else if (*character >= 'a' && *character <= 'z')
		return CHARACTER_IS_LOWER_CASE;
	else if (*character == '-')
		return CHARACTER_IS_HYPHEN;
	return CHARACTER_IS_INVALID;
}

///This function receives a HOSTENT struct pointer as input and prints the IPs that were retrived in the response, if there are any
void print_output_to_the_screen(HOSTENT *output)
{

	char *ip = (char*)malloc(sizeof(char) * IP_MAX_LENGTH), *tool; //IP string construction
	unsigned char label;
	int i = 0, size = 0, k = 0;
	while (*(output->h_addr_list + k) != NULL) {


		tool = ip;
		while (i < 4) {
			label = *(*(output->h_addr_list + k) + i);
			size = sprintf(tool, "%d", label);
			tool += size;
			*tool = '.';
			tool += 1;
			i++;
		}
		*(tool - 1) = '\0';
		if (check_ip_address(ip) == IP_ADDRESS_IS_VALID)
			printf("%s\n", ip);
		else
			printf("Response's IP address is invalid \n");
		k++; i = 0; size = 0;
	}
	free(output);
}




//$$$$$$$$$$$$$$$$$$$$$$$$$     DnsQuery.c    Functions    $$$$$$$$$$$$$$$$$$$$$$

///input: the domain name entered by the user (string), and the current request's id (number)
///output: Pointer to a QueryRFC1035  struct that will be sent to a DNS server later
QueryRFC1035* construct_message_for_sending(char* domain_name, unsigned short id)
{
	QueryRFC1035 *msg = (QueryRFC1035*)malloc(sizeof(QueryRFC1035));
	char progression = 0;
	msg->Question.QNAME	= (char*)malloc(sizeof(char)*NAME_LENGTH);
	
	///Header field construction
	msg->Header.ID = id;
	msg->Header.FLAGS = 0x0001;///0x80 says RA is on, which is not needed for queries so -> 0x00 (turnning it off) look at nslookup's wireshark capture
	msg->Header.QDCOUNT = 0x0100;
	msg->Header.ANCOUNT = 0x0000;
	msg->Header.NSCOUNT = 0x0000;
	msg->Header.ARCOUNT = 0x0000;
	
	///Question field construction
	construct_dname_for_message(msg, domain_name);
	msg->Question.QTYPE = 0x0100;
	msg->Question.QCLASS = 0x0100;
	return msg;
}
///Goal: This function aids us to build the domain name as needed in the RFC1035 Query's Question section
///Input: The Query's pointer, domain name(string)  
///Outputs: None. It updates the query's QNAME field
void construct_dname_for_message(QueryRFC1035 *msg, char* domain_name) 
{
	char *start = domain_name, *end = NULL, progression = 0, dot = '.', *temp = (char*)malloc(sizeof(char)*LABEL_SIZE);
	while (start != '\0') {
		end = strchr(domain_name + progression, dot);
		if (end == NULL){ /// This is the case of the last label. We may allow ourselves to act this way because we already assured the validity of the Domain Name 
			end = strchr(domain_name + progression, '\0');
			progression = progression + sprintf(progression + msg->Question.QNAME, "%c", end - start);
			string_between_strings(start, end, temp);
			progression = progression + sprintf(msg->Question.QNAME + progression, "%s", temp);
			start = '\0';
			continue; }
		///We found a dot in domain name -> we now update, as bytes, the string 
		progression = progression + sprintf(progression + msg->Question.QNAME, "%c", end - start);
		string_between_strings(start, end, temp);
		progression = progression + sprintf(msg->Question.QNAME + progression, "%s", temp);
		start = end + 1;///Moving forward to scan the next label
	}
	free(temp);
	sprintf(msg->Question.QNAME + progression, "%c", 0);
}
///Goal: Copy the string from source until stop pointer to a new string outcome. 
///Input: Receives two pointers to the same string (source & stop_pointer) and a pointer to a new allocated string (outcome). 
///Output: None. It updates the memory pointed to by outcome with a string of characters placed between the two former pointers
void string_between_strings(char* source, char* stop_pointer, char* outcome) 
{
	int len = stop_pointer - source;
	int i = 0;
	for (i = 0; i < len; i++)
	{
		*(outcome + i) = *(source + i);
	}
	*(outcome + i) = '\0';
}




///Goal: Send the query to the DNS server IP address inserted as input
///Input: Socket, Query struct pointer, string of the ip, the size of the query message after altering it to the format of the RFC 1035 (size_of_query)
///Output: integer = An appropriate message indicating the outcome of the Send operation.
int send_function(SOCKET s, QueryRFC1035 *msg, char *ip_address, int size_of_query)
{
	int number_of_bytes = 0;
	unsigned short port =53;
	char *mem = (char*)malloc(sizeof(char) * size_of_query);
	

	///Allocating memory for a socket address structure, setting its' values to zero and preparing it with the desired address
	SOCKADDR_IN *socket_address = (SOCKADDR_IN*)malloc(sizeof(SOCKADDR_IN));
	memset(socket_address, 0, sizeof(socket_address));
	socket_address->sin_family = PF_INET;
	socket_address->sin_addr.s_addr = inet_addr(ip_address);
	socket_address->sin_port = htons(port);
	

	///Copying the Query message to memory and replace its' the memory type from MessageRFC1035 
	///to char because this what "sendto"'s buffer is defined as. 
	///First, we prepare the memory, allocated for the buffer, by setting the addresses to zero.
	memset(mem, 0, size_of_query);
	set_memory_for_sending(mem, msg, size_of_query -16); ///The addition of 2 considers the zero character at the end AND the legth byte at the start, and the reduction of 16 considers the same domain name


	///Sending operation. number_of_bytes will allow us to measure the successfulness of the operation.
	number_of_bytes = sendto(s, mem, size_of_query, 0, (SOCKADDR*)socket_address, sizeof(*socket_address));
	///System call error check & print
	if(number_of_bytes == SOCKET_ERROR)
		printf("Send message operation failed with error: %d\n", WSAGetLastError());

	///Dynamic memory release
	free(socket_address);
	free(mem);
	///Output
	switch (number_of_bytes) {
	case 0:
		printf("Send didn't send data\n"); 
	case SOCKET_ERROR:
		return MESSAGE_WAS_NOT_SENT;
		break; 
	default:
		return MESSAGE_WAS_SENT;
	}
}
///Goal:This function sets the buffer which is meant to be used for the sending operation
///Input: Memory buffer (char*), Query struct pointer, the size of the domain name after altering it to the format of the RFC 1035 (domain_name_size)
///Output: None. This function updates the memory buffer with binary data
void set_memory_for_sending(char *memory, QueryRFC1035 *msg, int domain_name_size) 
{
	memcpy(memory, msg, 12);
	memcpy(memory + 12, msg->Question.QNAME, domain_name_size);
	memcpy(memory + 12+domain_name_size, &(msg->Question.QTYPE), 2); 
	memcpy(memory + 14+domain_name_size, &(msg->Question.QCLASS), 2);
}


///Goal: This function uses the "select" function to prepare the socket for receiving (in this case) the DNS server response to the query sent before
/// and by so reverting the receiving operation from being a blocking operation
///Input: Pointer of type fd_set -> meaning the socket we'd like to use to receive data
///Output: An appropriate message(integer) if the data arrived on time and ready for retrival. Prints Timeout message if waited too long
int identify_whether_data_has_returned(fd_set *set)
{
	int result;
	TIMEVAL *timelimit = (TIMEVAL*)malloc(sizeof(TIMEVAL)); //prehaps create a sub function for that too
	///TIMEVAL struct construction
	timelimit->tv_sec = 2;
	timelimit->tv_usec = 0;

	//select returns the number of file descriptor (=sockets) in all sets, or 0 if timeout expired, or -1 if error has occured (or SOCKET_ERROR)
	result = select(0, set, NULL, NULL, timelimit); 
	///System call error check & print
	if (result == SOCKET_ERROR)
		printf("Receive message operation failed with error: %d\n", WSAGetLastError()); 

	///Memory release
	free(timelimit);
	///Output
	switch (result) {
	case 0: //Need to add TIMEOUT error
		printf("TIMEOUT\n");
	case SOCKET_ERROR:
		return RECIEVE_MESSAGE_WILL_FAIL;
		break; //Perhaps it can be dropped
	default:
		return RECIEVE_MESSAGE_WILL_SUCCEED;
	}
}


///Goal: Recieve the respone from the DNS server IP address inserted as input
///Input: Socket, string of the ip, memory buffer to store the binary data of the response 
///Output: integer = An appropriate message indicating the outcome of the Receive operation.
int receive_function(SOCKET s, char *ip_address, char *mem)//, int id, int size_of_query) //message is the struct for the RFC 1035
{
	int number_of_bytes = 0, len_of_socaddr;
	unsigned short port = 53;
	

	///Allocating memory for a socket address structure, setting its' values to zero and preparing it with the desired address
	SOCKADDR_IN *socket_address = (SOCKADDR_IN*)malloc(sizeof(SOCKADDR_IN));
	memset(socket_address, 0, sizeof(socket_address));
	socket_address->sin_family = PF_INET;
	socket_address->sin_addr.s_addr = inet_addr(ip_address);
	socket_address->sin_port = htons(port);
	len_of_socaddr = sizeof(*socket_address); 


	///Receiving operation. number_of_bytes will allow us to measure the successfulness of the operation.
	number_of_bytes = recvfrom(s, mem, MAX_MESSAGE_SIZE , 0 , (SOCKADDR*)socket_address, &len_of_socaddr);
	///System call error check & print
	if (number_of_bytes == SOCKET_ERROR)
		printf("Receive message operation failed with error: %d\n", WSAGetLastError());


	
	free(socket_address);
	switch (number_of_bytes) {
	case 0:
		printf("Receive didn't receive data\n");
	case SOCKET_ERROR:
		return MESSAGE_WAS_NOT_RECEIVED;
		break; 
	default:
		return PROCEED_TO_ANALYZE_MESSAGE;
	}
}




///Goal: This function analyzes the response data and updates an AnswerRFC1035 struct with the answers received from the data
///Input: AnswerRFC1035 struct pointer, pointer to the binary memory buffer, QueryRFC1035 struct pointer (the query sent before), binary size of the query as before
///Output: Number of the answers which are IPv4 addresses Type = A (Although all answers will be stored in *msg)
int response_parsing_and_answer_construction(AnswerRFC1035 *msg, char *memory, QueryRFC1035 *query, int domain_name_size)
{
	int progression = 0, i=0, a = 0, flag = 1, real = 0;
	unsigned short ANCOUNT, offset = 0, TYPE, CLASS, RDLENGTH;
	ANSWER *current_answer = NULL;

	
	/// I use set_Header_and_Question_at_Answer in order to update the Response Message's Header & Question fields, from the buffer to the incoming response
	/// There, if I get the following failures, I will print the error message and exit with no further additional responses - which is why NO_DATA_RESPONSE
	/// else, we continue with the progression already made.
	///        FAILURES:      IDquery != IDreponse,   QR != 1,   RECODE !=0,   ANCOUNT == 0,   different domain names
	progression = set_Header_and_Question_at_Answer(msg, memory, query, domain_name_size);
	if (progression == NO_DATA_RESPONSE)
		return NO_DATA_RESPONSE;

	///Fifth Section: Answer Retrival after assuring they have type=A class=IN & IPv4 style IP
	msg->Answer = (ANSWER*)malloc(sizeof(ANSWER));
	current_answer = msg->Answer;
	current_answer->next = NULL;
	ANCOUNT = ((msg->Header.ANCOUNT >> 8) & 0x00FF) + ((msg->Header.ANCOUNT & 0x00FF) << 8);
	while (a < ANCOUNT) {
		///Allocating memory for Record & Record's Name
		current_answer->Record = (RESREC*)malloc(sizeof(RESREC));
		current_answer->Record->NAME = malloc(sizeof(char) * NAME_LENGTH);
		current_answer->Record->RDATA = NULL;

		///Updating the current answer's Record's Name
		progression = fill_NAME_or_RDATA(current_answer->Record->NAME, memory, progression);
		

		///Updating TYPE, CLASS, TTL, RDLENGTH & RDATA if answer is legal
		memcpy(&(current_answer->Record->TYPE), memory + progression, 2);
		TYPE = ( (current_answer->Record->TYPE >> 8) & 0x00FF )  +  ( (current_answer->Record->TYPE & 0x00FF) << 8 ); ///For the left element the &0x00FF is probably not needed because Header.ANCOUNT is unsigned short
		if (TYPE == 1) {
			current_answer->Validity = 1;
			real++; }
		else current_answer->Validity = 0;
		progression += 2;

		memcpy(&(current_answer->Record->CLASS), memory + progression, 2);
		CLASS = ( (current_answer->Record->CLASS >> 8) & 0x00FF )  +  ( (current_answer->Record->CLASS & 0x00FF) << 8 ); ///For the left element the &0x00FF is probably not needed because Header.ANCOUNT is unsigned short
		if (CLASS != 1) {
			printf("Answer %d is irrelavant - Mistake inbound\n", a); //no data response -> what am i supposed to do if there are more answer remaining to check????? ->UPDATED (V4)- NOT A GOOD ENOUGH RESPONSE
			current_answer->Validity = 0; }
		progression += 2;

		memcpy(&(current_answer->Record->TTL), memory + progression, 4);
		progression += 4;

		memcpy(&(current_answer->Record->RDLENGTH), memory + progression, 2);  
		RDLENGTH = ((current_answer->Record->RDLENGTH >> 8) & 0x00FF) + ((current_answer->Record->RDLENGTH & 0x00FF) << 8);
		progression += 2;

		/// TYPE == 1 -> Answer is an IP 
		if (current_answer->Validity == 1) { 
			current_answer->Record->RDATA = (unsigned char*)malloc(sizeof(unsigned char) * RDLENGTH); //IP string construction
			i = 0;
			while (i < RDLENGTH) {
				memcpy(current_answer->Record->RDATA + i, memory + progression, 1);
				progression += 1;
				i++;
			}
			*(current_answer->Record->RDATA + i) = '\0';
		}
		else {
			current_answer->Record->RDATA = (unsigned char*)malloc(sizeof(unsigned char) * NAME_LENGTH);
			///If Validity == 0 (TYPE !=1 ) the answer is not an IP address, but a domain name (or something else)
			progression = fill_NAME_or_RDATA(current_answer->Record->RDATA, memory, progression);
		}
		///Moving to next answer
		a++;
		///Updating Nested List with a new element
		current_answer->next = (ANSWER*)malloc(sizeof(ANSWER));
		current_answer = current_answer->next;
		current_answer->next = NULL;

	}
	///Setting last element is the Nested List so we can search for it later for Memory release
	current_answer->Validity = 5;
	

	/// We will no longer use the data buffer of the response because we are done analyzing 
	free(memory);
	return real; ///returning the number of the desired answers out of all answers
}
///Goal: This function fills the binary name of EITHER the NAME field or RDATA field of the Answer into the Answer Nested List element
///Input: Output string (memory) in which we insert the data, Memory buffer (char*), the binary progression that happend so far
///Output: Updated progression that considers the further bytes we scanned of the memory. Updated NAME OR RDATA fields of Anwer struct
int fill_NAME_or_RDATA(char *string, char *memory, int progression)
{
	unsigned short offset;
	unsigned char byte;
	int step = progression,flag = 1, i=0;
	memcpy(&byte, memory + progression, 1);
	while (byte != '\0') {
		if ((byte & 0xC0) >> 6 == 3) { //The byte scanned is an offset
			if (flag) { //WE ARRIVED AT THE FIRST OFFSET
				memcpy(&offset, memory + progression, 2);
				offset = (((offset >> 8) & 0x00FF) + ((offset & 0x00FF) << 8)) & 0x3FFF;
				progression += 2; // Offset is 2 octets
				step = offset;
				memcpy(&byte, memory + step, 1);
				flag = 0;
			}
			else {
				memcpy(&offset, memory + step, 2);
				offset = (((offset >> 8) & 0x00FF) + ((offset & 0x00FF) << 8)) & 0x3FFF;
				step = offset;
				memcpy(&byte, memory + step, 1);
			}
				///*size = */sprintf((*(msg->Answer + a))->NAME, "%s", memory + offset);
		}
		else {//The byte scanned isn't an offset
			if (flag) { //I HAVEN'T ARRIVED AT THE FIRST OFFSET IF EXISTS
				sprintf(string + i, "%c", *(memory + progression));
				progression += 1;
				memcpy(&byte, memory + progression, 1);
				if (byte == '\0')
					progression += 1; ///For the case where the name doesn't have an offset at any stage
			}
			else { //I HAVE ARRIVED AT THE FIRST OFFSET
				sprintf(string + i, "%c", *(memory + step));
				step += 1;
				memcpy(&byte, memory + step, 1);
			}
			i++;
		}
	}
	return progression;
}
///Goal: This function analyzes the response data (memory buffer) and updates the Header & Question fields in AnswerRFC1035 struct 

/// & ALSO IT DEALS THE VARIOUS "RESPONSE" ERRORS ==== ID, QR, RCODE, ANCOUNT etc. It prints appropriate messages of the errors!!!!!!

///Input: AnswerRFC1035 struct pointer, pointer to the binary memory buffer, QueryRFC1035 struct pointer (the query sent before), binary size of the query as before
///Output:  Updated progression that considers the further bytes we scanned of the memory. Updated Header & Question fields of AnswerRFC1035 struct
int set_Header_and_Question_at_Answer(AnswerRFC1035 *msg, char *memory, QueryRFC1035 *query, int size_of_query)
{
	int progression = 0;
	unsigned short QR, RCODE, ANCOUNT;

	///First Section: Query's and Answer's IDs comparison -if the don't match there is no reason to proceed
	memcpy(&(msg->Header.ID), memory, 2);
	if (msg->Header.ID != query->Header.ID) {
		printf("We received the wrong packet\n");
		return NO_DATA_RESPONSE;
	}
	progression += 2;


	///Second Section: Response as an Answer validity check via QR     &     RCODE classification 
	memcpy(&(msg->Header.FLAGS), memory + progression, 2);
	///After memcpy the position are reversed (which is really an Endians matter) meaning QR is placed at the seventh LSB,
	///and from there we apply bitwise 'AND' to place zero at the remaining bits
	QR = (msg->Header.FLAGS >> 7) & 0x001;
	if (QR != 1) {
		printf("This is not a response\n");
		return NO_DATA_RESPONSE;
	}
	///After memcpy the position are reversed meaning RCODE is placed from eigth LSB to eleventh LSB,
	///and from there we apply bitwise 'AND' to place zero at the remaining bits
	
	RCODE = (msg->Header.FLAGS >> 8) & 0x0F;
	switch (RCODE) {
	case FORMAT_ERROR://no data response
		return NO_DATA_RESPONSE;
	case SERVER_FAILURE:
		printf("ERROR: SERVER FAILURE\n"); return NO_DATA_RESPONSE;
	case NONEXISTENT_DOMAIN:
		printf("ERROR: NONEXISTENT\n"); return NO_DATA_RESPONSE;
	case NOT_IMPLEMENTED:
		printf("ERROR: NOT IMPLEMNTED\n"); return NO_DATA_RESPONSE;
	case QUERY_REFUSED:
		printf("ERROR: REFUSED\n"); return NO_DATA_RESPONSE;
	case NO_ERROR: break; //CONTINUE
	}
	progression += 2;


	///Third Section: Answer count -> if it is a postive number than we proceed to evaluate the Answers 
	memcpy(&(msg->Header.QDCOUNT), memory + progression, 2);
	progression += 2;
	memcpy(&(msg->Header.ANCOUNT), memory + progression, 2);
	///Rearranging the number to overcome Endians order
	ANCOUNT = ((msg->Header.ANCOUNT >> 8) & 0x00FF) + ((msg->Header.ANCOUNT & 0x00FF) << 8); ///For the left element the &0x00FF is probably not needed because Header.ANCOUNT is unsigned short
	if (ANCOUNT == 0) {
		printf("There are no answers\n"); //no data response
		return NO_DATA_RESPONSE;
	}
	progression += 2;
	memcpy(&(msg->Header.NSCOUNT), memory + progression, 2);
	progression += 2;
	memcpy(&(msg->Header.ARCOUNT), memory + progression, 2);
	progression += 2;


	///Fourth Section: Question part of the response
	msg->Question.QNAME = (char*)malloc(sizeof(char)*size_of_query); //assuming dname is same
	memcpy(msg->Question.QNAME, memory + progression, size_of_query);
	progression += size_of_query;
	if (strcmp(msg->Question.QNAME, query->Question.QNAME) != 0) {
		printf("Domain name of the query in the messages don't match\n");
		return NO_DATA_RESPONSE;
	}
	memcpy(&(msg->Question.QTYPE), memory + progression, 2);
	progression += 2;
	memcpy(&(msg->Question.QCLASS), memory + progression, 2);
	progression += 2;

	return progression;
}




///Goal: This function arranges the answers in a HOSTENT struct, and prepare it for printing
///Input: Hostent struct point (allocated beforehand), AnswerRFC1035 struct pointer, the number of DESIRED IP answers
///Output: None. Updates the HOSTENT struct.
void construct_hostent(HOSTENT *output, AnswerRFC1035 *msg, int no_of_answers)
{
	int i =0;
	ANSWER* answers = msg->Answer;

	output->h_addrtype = AF_INET;
	output->h_length = 4;
	output->h_addr_list = (char**)malloc(sizeof(char*)*no_of_answers);
	while ((i < no_of_answers) || (answers == NULL)) {
		if (answers->Validity == 0) {/// IP answers (A type)
			answers = answers->next;
			continue; } ///FOR FUTURE USE I CAN CHANGE THIS SECTION TO INCLUE   CNAME   Answers
 		else if (answers->Validity == 1) {/// String answers (CNAME type)
			*(output->h_addr_list + i) = (char*)malloc(sizeof(char)*output->h_length);
			strcpy(*(output->h_addr_list + i), answers->Record->RDATA);
			answers = answers->next;
			i++;
		}
	}
	///Response Message Memory allocated release
	free_function_Nested_List(msg->Answer);
	free(msg->Question.QNAME);
	free(msg);

	///Setting HOSTENT struct pointer's last element in its' list to NULL to have indication at print
	*(output->h_addr_list + no_of_answers) = NULL;
}
///Goal: This function releases the Nested List data of the answers 
void free_function_Nested_List(ANSWER *answers)
{
	ANSWER *node;
	while (answers->Validity != 5) /// 5 was used as an indicator (it was defined in response_parsing_and_answer_construction) 
	{
		node = answers;
		answers = answers->next;
		free(node);
	}
	///Last element release
	free(answers);
}

///Goal: This function releases the fd_set set and the query of QueryRFC1035 struct
void free_function_1D(fd_set *set, QueryRFC1035 *query)
{
	free(set);
	if (query != NULL) {
		free(query->Question.QNAME);
		free(query);
	} /// There WAS a need to free QNAME separately
}


