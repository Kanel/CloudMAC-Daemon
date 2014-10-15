#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#define PORT    1999
#define BUFFER_LENGTH  512
#define SELECT_TIMEOUT_SECONDS 1
#define ACK_INTERFACES 32
#define FILE_NAME_BUFFER_LENGTH 100

int serverfd;
struct sockaddr_in serv_addr;

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

char * readfile(const char * filename)
{
	char file_buffer[BUFFER_LENGTH];
	char * content;
	FILE * file = fopen(filename, "r");

	if(file == NULL)
	{
		char * result = malloc(5);

		strcpy(result, "none");

		return result;
	}
	fread(file_buffer, BUFFER_LENGTH, 1, file);
	fclose(file);

	content = malloc(strlen(file_buffer) + 1);

	strcpy(content, file_buffer);

	content[strlen(file_buffer) - 2] = 0; // Remove trailing linebreaks

	return content;
}

int main()
{
	int i;
	int clientfd;
	int client_len;
	int interfaces[ACK_INTERFACES];
	char buffer[BUFFER_LENGTH];
	struct sockaddr_in cli_addr;
	struct timeval tv;
	fd_set active_set, reference_set;

	printf("Setting up Server\n");
	
	if (setup_server(PORT) != 0)
	{
		printf("Bind Failed\n");
		return -1;
	}	

	printf("Setting up Interfaces\n");
	for (i = 0; i < ACK_INTERFACES; i++)
	{
		interfaces[i] = 0;

		printf("iw dev wlan0.%d del\n", i);
		snprintf(buffer, BUFFER_LENGTH, "iw dev wlan0.%d del", i);		
		system(buffer);
		sleep(1);
		printf("iw phy phy0 interface add wlan0.%d type managed", i);
		snprintf(buffer, BUFFER_LENGTH, "iw phy phy0 interface add wlan0.%d type managed", i);		
		system(buffer);
		sleep(1);
	}

	printf("Address Bound\n");
	printf("Listening for connections\n");
	listen(serverfd, 1);

	FD_ZERO(&reference_set);
	FD_SET(serverfd, &reference_set);

	while (1)
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
			message_length = strlen(buffer);		

			if (read_bytes > 0)
			{
				if(buffer[message_length - 2] == '\r' || 
				   buffer[message_length - 2] == '\n')
				{
					buffer[message_length - 2] = '\0';
				}
				if(strcmp(buffer, "get") == 0)
				{
					for (i = 0; i < ACK_INTERFACES; i++)
					{
						char state_file[FILE_NAME_BUFFER_LENGTH];
						char mac_file[FILE_NAME_BUFFER_LENGTH];
						char * wlan0state;
						char * wlan0mac;
						char result[BUFFER_LENGTH];
					
						snprintf(state_file, FILE_NAME_BUFFER_LENGTH, "/sys/class/net/wlan0.%d/operstate", i);
						snprintf(mac_file, FILE_NAME_BUFFER_LENGTH, "/sys/class/net/wlan0.%d/phy80211/macaddress", i);
					
						wlan0state = readfile(state_file);
						wlan0mac = readfile(mac_file);
					
						snprintf(result, BUFFER_LENGTH, "wlan0.%d: %s %s\n", i, wlan0state, wlan0mac);
						free(wlan0state);
						free(wlan0mac);
					
						write(clientfd, result, strlen(result) + 1);
					}
				}
				
			}
			close(clientfd);
		}
		else
		{
			printf("Nothing here!\n");
		}
	}
}
