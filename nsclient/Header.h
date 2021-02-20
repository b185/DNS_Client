#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "winsock2.h"

#ifndef HEADER_FILE
#define HEADER_FILE

//Constants
#define NAME_LENGTH 253
#define OCTET 1
#define LABEL_SIZE 63
#define MAX_MESSAGE_SIZE 512
#define IP_MAX_LENGTH 16




//Messages
#define IP_ADDRESS_IS_VALID 1
#define IP_ADDRESS_IS_INVALID 0
#define LABEL_IS_VALID 1
#define LABEL_IS_INVALID 0

#define CHARACTER_IS_INVALID 0
#define CHARACTER_IS_DIGIT 1
#define CHARACTER_IS_UPPER_CASE 2
#define CHARACTER_IS_LOWER_CASE 3
#define CHARACTER_IS_HYPHEN 4
#define DOMAIN_NAME_IS_INVALID -1
#define QUIT_WAS_INSERTED 0
#define DOMAIN_NAME_IS_VALID 1

#define MESSAGE_WAS_SENT 1
#define MESSAGE_WAS_NOT_SENT 0

#define RECIEVE_MESSAGE_WILL_SUCCEED 1
#define RECIEVE_MESSAGE_WILL_FAIL 0

#define PROCEED_TO_ANALYZE_MESSAGE 1
#define MESSAGE_WAS_NOT_RECEIVED 0


#define FORMAT_ERROR 1
#define SERVER_FAILURE 2
#define NONEXISTENT_DOMAIN 3
#define NOT_IMPLEMENTED 4
#define QUERY_REFUSED 5

#define NO_DATA_RESPONSE -1







//Resource Record structure
typedef struct _RESREC {
	char *NAME; 
	unsigned short TYPE;
	unsigned short CLASS;
	unsigned int TTL;
	unsigned short RDLENGTH;
	unsigned char *RDATA;
}RESREC;


//Answer structure - PAY ATTENTION !!!! - Nested List Struct
typedef struct _ANSWER {
	unsigned char Validity; /// Is the answer an IP
	RESREC *Record; ///Answer's information
	struct _ANSWER *next; ///Next Answer
}ANSWER;


//Question structure
typedef struct _QUESTION {
	unsigned short QTYPE; ///16 bits = 2 octets
	unsigned short QCLASS;
	char *QNAME; /// Can not be with predetermined length because domain names vary
}QUESTION;


//Header structure
typedef struct _HEADER {
	unsigned short ID;
	unsigned short FLAGS;  /// Insert values in the following order: RA Z RCODE QR OPCODE AA TC RD
	unsigned short QDCOUNT;
	unsigned short ANCOUNT;
	unsigned short NSCOUNT;
	unsigned short ARCOUNT;
}HEADER;




//RFC 1035 Query Message structure
typedef struct _QueryRFC1035 {
	HEADER Header;
	QUESTION Question;
}QueryRFC1035;

//RFC 1035 Answer Message structure
typedef struct _AnswerRFC1035 {
	HEADER Header;
	QUESTION Question;
	ANSWER *Answer; /// NESTED LIST SO WE CAN HAVE VARIABLE AMOUNT OF ANSWERS
}AnswerRFC1035;





//--------------------------------------Functions Headers------------------------
///main functions
int check_ip_address(char* ip_address);
int check_label(char *sect);

int check_domain_name(char* domain_name);
int check_character(char* character);

HOSTENT* dnsQuery(char *ip_address, char *domain_name, unsigned short id);

void print_output_to_the_screen(HOSTENT *output);


///dnsQuery functions
QueryRFC1035* construct_message_for_sending(char* domain_name, unsigned short id);
void construct_dname_for_message(QueryRFC1035 *msg, char* domain_name);
void string_between_strings(char* source, char* stop_pointer, char* outcome);

int send_function(SOCKET s, QueryRFC1035 *msg, char *ip_address, int domain_name_size);
void set_memory_for_sending(char *memory, QueryRFC1035 *msg, int domain_name_size);

int identify_whether_data_has_returned(fd_set *set);

int receive_function(SOCKET s, char *ip_address, char *mem);// , int id, int size_of_query);

int response_parsing_and_answer_construction(AnswerRFC1035 *msg, char *memory, QueryRFC1035 *query, int size_of_query);
int fill_NAME_or_RDATA(char *string, char *memory, int progression);
int set_Header_and_Question_at_Answer(AnswerRFC1035 *msg, char *memory, QueryRFC1035 *query, int size_of_query);

void construct_hostent(HOSTENT *output, AnswerRFC1035 *msg, int no_of_answers);
void free_function_Nested_List(ANSWER *answers);

void free_function_1D(fd_set *set, QueryRFC1035 *query);

#endif