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
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <stdint.h>

#define PORT    1999
#define BUFFER_LENGTH  512
#define SELECT_TIMEOUT_SECONDS 1
#define ACK_INTERFACES 32
#define FILE_NAME_BUFFER_LENGTH 100
#define TRUE 1
#define FALSE 0
#define MAC_ADDRESS_LENGTH 19 // Includes null termianter
#define MAC_SCANF "%18s"      //

/* Announce Stuff */
#define IDLE_ANNOUNCE_TIME 1000000
#define CLOUDMAC_ETHER_TYPE 0x1337
#define DEFAULT_CONFIG_INTERFACE "eth1"
#define DEFAULT_SEND_INTERFACE "eth0"
#define DESTINATION_MAC_1 255
#define DESTINATION_MAC_2 255
#define DESTINATION_MAC_3 255
#define DESTINATION_MAC_4 255
#define DESTINATION_MAC_5 255
#define DESTINATION_MAC_6 255

struct ethernet_packet
{
	struct ether_header header;
	uint8_t payload[16];
};

struct announcement_config
{
	struct ethernet_packet packet;
	struct sockaddr_ll socket_address;
	int socket;
	char config_interface_name[IFNAMSIZ];
};

int init_announce(char * send_interface_name, char * config_interface_name, struct announcement_config * config)
{
	struct ifreq interface_idx;
	struct ifreq interface_mac;	
	
	memset(config, 0, sizeof(struct announcement_config));
	strncpy(config->config_interface_name, config_interface_name, IFNAMSIZ);
	
	/* Open socket. */	
	if ((config->socket = socket(AF_PACKET, SOCK_RAW, SOCK_RAW)) == -1)
	{
		perror("socket");
		
		return -1;
	}
	
	/* Get interface index to send the packets on. */
	memset(&interface_idx, 0, sizeof(struct ifreq));
	strncpy(interface_idx.ifr_name, send_interface_name, IFNAMSIZ - 1);
	
	if (ioctl(config->socket, SIOCGIFINDEX, &interface_idx) < 0)
	{
	    perror("SIOCGIFINDEX");		
		
		return -2;
	}
		
	/* Get the MAC address to send the packets on. */
	memset(&interface_mac, 0, sizeof(struct ifreq));
	strncpy(interface_mac.ifr_name, send_interface_name, IFNAMSIZ - 1);
	
	if (ioctl(config->socket, SIOCGIFHWADDR, &interface_mac) < 0)
	{
	    perror("SIOCGIFHWADDR");
		
		return -3;
	}
	
	/* Construct the static component of the packet. */	
	config->packet.header.ether_dhost[0] = DESTINATION_MAC_1;
	config->packet.header.ether_dhost[1] = DESTINATION_MAC_2;
	config->packet.header.ether_dhost[2] = DESTINATION_MAC_3;
	config->packet.header.ether_dhost[3] = DESTINATION_MAC_4;
	config->packet.header.ether_dhost[4] = DESTINATION_MAC_5;
	config->packet.header.ether_dhost[5] = DESTINATION_MAC_6;
	config->packet.header.ether_shost[0] = ((uint8_t *)&interface_mac.ifr_hwaddr.sa_data)[0];
	config->packet.header.ether_shost[1] = ((uint8_t *)&interface_mac.ifr_hwaddr.sa_data)[1];
	config->packet.header.ether_shost[2] = ((uint8_t *)&interface_mac.ifr_hwaddr.sa_data)[2];
	config->packet.header.ether_shost[3] = ((uint8_t *)&interface_mac.ifr_hwaddr.sa_data)[3];
	config->packet.header.ether_shost[4] = ((uint8_t *)&interface_mac.ifr_hwaddr.sa_data)[4];
	config->packet.header.ether_shost[5] = ((uint8_t *)&interface_mac.ifr_hwaddr.sa_data)[5];
	config->packet.header.ether_type = htons(CLOUDMAC_ETHER_TYPE);
	
	/* configure socket address. */
	memset(&config->socket_address, 0, sizeof(struct sockaddr_ll));

	config->socket_address.sll_addr[0] = DESTINATION_MAC_1;
	config->socket_address.sll_addr[1] = DESTINATION_MAC_2;
	config->socket_address.sll_addr[2] = DESTINATION_MAC_3;
	config->socket_address.sll_addr[3] = DESTINATION_MAC_4;
	config->socket_address.sll_addr[4] = DESTINATION_MAC_5;
	config->socket_address.sll_addr[5] = DESTINATION_MAC_6;
	config->socket_address.sll_halen = ETH_ALEN;
	config->socket_address.sll_ifindex = interface_idx.ifr_ifindex;
	
	return 0;
}

int announce(struct announcement_config * config)
{
	char * ip_buffer;
	struct ifreq interface_ip;
	
	/* Get the IP address for the configuration interface. */
	memset(&interface_ip, 0, sizeof(struct ifreq));
	strncpy(interface_ip.ifr_name, config->config_interface_name, IFNAMSIZ - 1);
	
	interface_ip.ifr_addr.sa_family = AF_INET;
	
	if (ioctl(config->socket, SIOCGIFADDR, &interface_ip) < 0)
	{
		perror("SIOCGIFADDR");
		
		return -1;
	}
	
	/* Set packet payload. */
	ip_buffer = inet_ntoa(((struct sockaddr_in *)&interface_ip.ifr_addr)->sin_addr);
	
	strncpy(config->packet.payload, ip_buffer, sizeof(*config->packet.payload));

	/* Send packet */
	if (sendto(config->socket, &config->packet, sizeof(config->packet), 0, (struct sockaddr*)&config->socket_address, sizeof(struct sockaddr_ll)) < 0)
	{
		perror("SENDTO");
	}	
	return 0;
}

/* Other Stuff */
const char * del_ack_interfaces = "iw dev ack%d del";
const char * create_ack_interfaces = "iw phy phy0 interface add ack%d type managed"; 
const char * ack_interface_operstate = "/sys/class/net/ack%d/operstate";
const char * ack_interface_flags = "/sys/class/net/ack%d/flags";
const char * ack_interface_mac_address = "/sys/class/net/ack%d/address";
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

// Seems to not work on CloudMAC WTPs allways reported "down" or "unknown".
char * getOperstate(int i, char * buffer, int buffer_length)
{
	char mac_file[FILE_NAME_BUFFER_LENGTH];

	snprintf(mac_file, FILE_NAME_BUFFER_LENGTH, ack_interface_operstate, i);
	
	return readfile(mac_file, buffer, buffer_length);
}

char * getState(int i, char * buffer, int buffer_length)
{
	int flags;
	char mac_file[FILE_NAME_BUFFER_LENGTH];

	snprintf(mac_file, FILE_NAME_BUFFER_LENGTH, ack_interface_flags, i);
	readfile(mac_file, buffer, buffer_length);
	sscanf(buffer, "%x", &flags);
	printf("%d\n", flags);
	// The elast significant bit indicates if the interface is up.
	if ((flags & 0x1) == 0x1)
	{
		snprintf(buffer, buffer_length, "up");
	}
	else
	{
		snprintf(buffer, buffer_length, "down");
	}
	return buffer;
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
	unsigned long announce_expires = 0;
	struct record records[ACK_INTERFACES];
	struct sockaddr_in cli_addr;
	struct timeval tv;
	fd_set active_set, reference_set;
	struct announcement_config config;

	keepRunning = TRUE;

	signal(SIGINT, INThandler);	
	memset(records, 0, sizeof(records));

	// Announce configuration.
	printf("Initializing Announce Configuration\n");
	
	if (init_announce(DEFAULT_SEND_INTERFACE, DEFAULT_CONFIG_INTERFACE, &config) < 0)
	{
		printf("Initialization failed\n");
		
		return -1;
	}
	
	// Initialize listening socket.
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
	listen(serverfd, 10);

	FD_ZERO(&reference_set);
	FD_SET(serverfd, &reference_set);

	while (keepRunning == TRUE)
	{
		tv.tv_sec = (long)SELECT_TIMEOUT_SECONDS;
		tv.tv_usec = 0;

		active_set = reference_set;
		
		// Command cycle.
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

				// Commands.
				if (strncmp(buffer, "status index", 12) == 0)
				{
					unsigned int slot;
					char mac[MAC_ADDRESS_LENGTH];

					sscanf(buffer, "status index %u", &slot);

					if (0 <= slot && slot < ACK_INTERFACES)
					{
						char state[BUFFER_LENGTH];
						char mac[BUFFER_LENGTH];

						getState(slot, state, BUFFER_LENGTH);
						getMacAddress(slot, mac, BUFFER_LENGTH);

						snprintf(buffer, BUFFER_LENGTH, "ack%d: %s %s %lu\n", slot, state, mac, records[slot].expires);

						write(clientfd, buffer, strlen(buffer) + 1);
					}
					else
					{
						snprintf(buffer, BUFFER_LENGTH, "Index out of bounds\n");
						write(clientfd, buffer, strlen(buffer) + 1);
					}
				}
				else if (strncmp(buffer, "status mac", 10) == 0)
				{
					int found_slot = -1;
					char mac[MAC_ADDRESS_LENGTH];

					//snprintf(sad, bah, formatting_string, MAC_ADDRESS_LENGTH - 1);
					sscanf(buffer, "status mac " MAC_SCANF, mac);

					for (i = 0; i < ACK_INTERFACES; i++)
					{
						if (strncmp(mac, records[i].mac, 19) == 0)
						{
							found_slot = i;
						
							break;
						}
					}
					if (found_slot != -1)
					{
						char state[BUFFER_LENGTH];
						char mac[BUFFER_LENGTH];

						getState(found_slot, state, BUFFER_LENGTH);
						getMacAddress(found_slot, mac, BUFFER_LENGTH);

						snprintf(buffer, BUFFER_LENGTH, "ack%d: %s %s %lu\n", found_slot, state, mac, records[found_slot].expires);

						write(clientfd, buffer, strlen(buffer) + 1);
					}
					else
					{
						snprintf(buffer, BUFFER_LENGTH, "Lease not found\n");
						write(clientfd, buffer, strlen(buffer) + 1);
					}
				}
				else if (strncmp(buffer, "status", 8) == 0)
				{
					for (i = 0; i < ACK_INTERFACES; i++)
					{
						char state[BUFFER_LENGTH];
						char mac[BUFFER_LENGTH];

						getState(i, state, BUFFER_LENGTH);
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
		
					sscanf(buffer, "lease " MAC_SCANF " %u", mac, &timeout);					
					
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
						getState(found_slot, interface_state, BUFFER_LENGTH);
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
						
						// Try until the interface is ready.
						while(system(buffer) != 0)
						{
							usleep(50);
						}

						// Write interface state to client.
						getState(empty_slot, interface_state, BUFFER_LENGTH);
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
		// Cleanup cycle.
		unsigned long now = getEpochTime();

		for (i = 0; i < ACK_INTERFACES; i++)
		{
			if (records[i].expires != 0 && records[i].expires < now)
			{
				printf("%lu: Lease for %s expired\n", now, records[i].mac);
				memset(&records[i], 0, sizeof(records[i]));

				// Turn off the interface.
				snprintf(buffer, BUFFER_LENGTH, ack_interface_deactivate, i);
				system(buffer);
			}
		}
		// Announce cycle.
		if (announce_expires < now)
		{
			announce_expires = now + IDLE_ANNOUNCE_TIME;

			printf("Announcing\n");
			announce(&config);
		}
		
	}
	printf("\nShutting down!\n");
	cleanup();

	return 0;
}
