#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <sys/timeb.h>

#define PORT    1999
#define BUFFER_LENGTH  512
#define SELECT_TIMEOUT_SECONDS 1
#define ACK_INTERFACES 32
#define FILE_NAME_BUFFER_LENGTH 100
#define TRUE 1
#define FALSE 0
#define MAC_ADDRESS_LENGTH 19 // Includes null termianter

const char * del_ack_interfaces = "iw dev ack%d del";
const char * create_ack_interfaces = "iw phy phy0 interface add ack%d type managed"; 
const char * ack_interface_operstate = "/sys/class/net/ack%d/operstate";
const char * ack_interface_mac_address = "/sys/class/net/ack%d/phy80211/macaddress";
const char * ack_interface_set_mac = "ifconfig ack%d hw ether %s";
const char * ack_interface_activate = "ifconfig ack%d up";
const char * ack_interface_deactivate = "ifconfig ack%d down";

int serverfd;
struct sockaddr_in serv_addr;
int keepRunning;

struct record {
	char mac[MAC_ADDRESS_LENGTH];
	unsigned long expires;
};

void cleanup()
{
	int  i;
	char buffer[BUFFER_LENGTH];
	
	for (i = 0; i < ACK_INTERFACES; i++)
	{
		printf(del_ack_interfaces, i);
		printf("\n");
		snprintf(buffer, BUFFER_LENGTH, del_ack_interfaces, i);		
		system(buffer);
	}
}

void  INThandler(int sig)
{
	if (keepRunning == FALSE)
	{
		cleanup();
		exit(0);
	}
	else
	{
		printf("Shutting down!\n");

		keepRunning = FALSE;	
	}
}

int setup_server(int port)
{
	serverfd = socket(AF_INET, SOCK_STREAM, 0);

	if (serverfd < 0)
	{
		return -1;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);

	int yes=1;
	setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	
	if (bind(serverfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0)
		return -2;
	return 0;
}

char * readfile(const char * filename, char * buffer, int buffer_length)
{
	char file_buffer[BUFFER_LENGTH];
	char * content;
	FILE * file = fopen(filename, "r");
	int read_bytes;

	if(file == NULL)
	{
		char * result = malloc(5);

		strcpy(result, "none");

		return result;
	}
	read_bytes = fread(buffer, 1, buffer_length, file);

	fclose(file);

	// Remove trailing linebreaks. 
	if (buffer[read_bytes - 2] == '\r')
	{
		buffer[read_bytes - 2] = 0;
	}
	else if (buffer[read_bytes - 1] == '\n')
	{
		buffer[read_bytes - 1] = 0;
	}
	else
	{
		buffer[read_bytes] = 0;
	}

	return buffer;
}

unsigned long getEpochTime()
{
	struct timeb time;

	ftime(&time);

	return time.time * 1000 + time.millitm;
}

char * getOperstate(int i, char * buffer, int buffer_length)
{
	char mac_file[FILE_NAME_BUFFER_LENGTH];

	snprintf(mac_file, FILE_NAME_BUFFER_LENGTH, ack_interface_operstate, i);
	
	return readfile(mac_file, buffer, buffer_length);
}

char * getMacAddress(int i, char * buffer, int buffer_length)
{
	char state_file[FILE_NAME_BUFFER_LENGTH];

	snprintf(state_file, FILE_NAME_BUFFER_LENGTH, ack_interface_mac_address, i);
	
	return readfile(state_file, buffer, buffer_length);
}

int main()
{
	int i;
	int clientfd;
	int client_len;
	char buffer[BUFFER_LENGTH];
	struct record records[ACK_INTERFACES];
	struct sockaddr_in cli_addr;
	struct timeval tv;
	fd_set active_set, reference_set;
	
	keepRunning = TRUE;

	signal(SIGINT, INThandler);	
	memset(records, 0, sizeof(records));

	printf("Setting up Server\n");
	
	if (setup_server(PORT) != 0)
	{
		printf("Bind Failed\n");
		return -1;
	}

	printf("Setting up Interfaces\n");
	for (i = 0; i < ACK_INTERFACES; i++)
	{
		printf(del_ack_interfaces, i);
		printf("\n");
		snprintf(buffer, BUFFER_LENGTH, del_ack_interfaces, i);		
		system(buffer);

		printf(create_ack_interfaces, i);
		printf("\n");
		snprintf(buffer, BUFFER_LENGTH, create_ack_interfaces, i);		
		system(buffer);
	}

	printf("Address Bound\n");
	printf("Listening for connections\n");
	listen(serverfd, 1);

	FD_ZERO(&reference_set);
	FD_SET(serverfd, &reference_set);

	while (keepRunning == TRUE)
	{
		tv.tv_sec = (long)SELECT_TIMEOUT_SECONDS;
		tv.tv_usec = 0;

		active_set = reference_set;
		
		if (select(serverfd + 1, &active_set, (fd_set *)0, (fd_set *)0, &tv) > 0)
		{
			int message_length;
			int read_bytes;

			client_len = sizeof(cli_addr);
			clientfd = accept(serverfd, (struct sockaddr *)&cli_addr, &client_len);
			read_bytes = read(clientfd, buffer, BUFFER_LENGTH);
			buffer[read_bytes] = 0;		

			if (read_bytes > 0)
			{
				// Remove trailing linebreaks.
				if (buffer[read_bytes - 2] == '\r')
				{
					buffer[read_bytes - 2] = 0;
				}
				else if (buffer[read_bytes - 1] == '\n')
				{
					buffer[read_bytes - 1] = 0;
				}
				else
				{
					buffer[read_bytes] = 0;
				}

				if (strncmp(buffer, "status", 7) == 0)
				{
					for (i = 0; i < ACK_INTERFACES; i++)
					{
						char state[BUFFER_LENGTH];
						char mac[BUFFER_LENGTH];

						getOperstate(i, state, BUFFER_LENGTH);
						getMacAddress(i, mac, BUFFER_LENGTH);
					
						snprintf(buffer, BUFFER_LENGTH, "ack%d: %s %s %lu\n", i, state, mac, records[i].expires);
					
						write(clientfd, buffer, strlen(buffer) + 1);
					}
				}
				else if (strncmp(buffer, "records", 7) == 0)
				{
					for (i = 0; i < ACK_INTERFACES; i++)
					{
						snprintf(buffer, BUFFER_LENGTH, "record-%d: %s %lu\n", i, records[i].mac, records[i].expires);
						printf("--%s--\n", records[i].mac);
						write(clientfd, buffer, strlen(buffer) + 1);
					}
				}
				else if (strncmp(buffer, "lease", 5) == 0)
				{
					int empty_slot = -1;
					int found_slot = -1;
					char mac[MAC_ADDRESS_LENGTH];
					char interface_state[BUFFER_LENGTH];
					char interface_mac[BUFFER_LENGTH];
					unsigned int timeout;
					unsigned long now = getEpochTime();				 
		
					sscanf(buffer, "lease %s %u", mac, &timeout);
					
					for (i = 0; i < ACK_INTERFACES; i++)
					{
						if (strncmp(mac, records[i].mac, 19) == 0)
						{
							found_slot = i;

							break;
						}
						else if (records[i].expires == 0)
						{
							empty_slot = i;
						}
					}
					if (found_slot != -1)
					{
						records[found_slot].expires = getEpochTime() + timeout;

						printf("%lu: Lease for %s extended, expires %lu\n", now, records[found_slot].mac, records[found_slot].expires);

						// Write interface state to client.
						getOperstate(found_slot, interface_state, BUFFER_LENGTH);
						getMacAddress(found_slot, interface_mac, BUFFER_LENGTH);
					
						snprintf(buffer, BUFFER_LENGTH, "ack%d: %s %s %lu\n", found_slot, interface_state, interface_mac, records[i].expires);
						write(clientfd, buffer, strlen(buffer) + 1);
					}
					else if (empty_slot != -1)
					{
						strncpy(records[empty_slot].mac, mac, MAC_ADDRESS_LENGTH);

						records[empty_slot].mac[MAC_ADDRESS_LENGTH - 1] = 0; // Make sure it is null terminated.
						records[empty_slot].expires = getEpochTime() + timeout;

						printf("%lu: Added lease for %s expires %lu\n", now, records[empty_slot].mac, records[empty_slot].expires);

						// Turn off the interface.
						snprintf(buffer, BUFFER_LENGTH, ack_interface_deactivate, empty_slot);
						system(buffer);

						// Set MAC adress.
						snprintf(buffer, BUFFER_LENGTH, ack_interface_set_mac, empty_slot, records[empty_slot].mac);
						system(buffer);

						// Turn on interface.
						snprintf(buffer, BUFFER_LENGTH, ack_interface_activate, empty_slot);
						system(buffer);

						// Write interface state to client.
						getOperstate(empty_slot, interface_state, BUFFER_LENGTH);
						getMacAddress(empty_slot, interface_mac, BUFFER_LENGTH);
					
						snprintf(buffer, BUFFER_LENGTH, "ack%d: %s %s %lu\n", empty_slot, interface_state, interface_mac, records[i].expires);
						write(clientfd, buffer, strlen(buffer) + 1);
					}
					else
					{
						snprintf(buffer, BUFFER_LENGTH, "No available interface\n");
						write(clientfd, buffer, strlen(buffer) + 1);
					}
				}
				else
				{
					snprintf(buffer, BUFFER_LENGTH, "Unknown Command\n");
					write(clientfd, buffer, strlen(buffer) + 1);
				}
				
			}
			close(clientfd);
		}
		else
		{
			unsigned long now = getEpochTime();

			for (i = 0; i < ACK_INTERFACES; i++)
			{
				if (records[i].expires != 0 && records[i].expires < now)
				{
					printf("%lu: Lease for %s expired\n", now, records[i].mac);
					memset(&records[i], 0, sizeof(records[i]));
				}
			}
		}
	}
	printf("\nShutting down!\n");		
	cleanup();

	return 0;
}
