/* UChat Server by Lukas Becker
UNIX Datagram Socket chat server
Usage: ./uchat_ser <num clients>
*/

// timestamps

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#define SERVER  "/tmp/uchat_ser"
#define CLIENT  "/tmp/uchat_cli"
#define BUFFER 4096
#define REGISTER_CHAR '#'
#define DISC_CHAR '%'

char* calctime() {
	time_t t;
   	struct tm *tmp;
   	t = time(NULL);
   	tmp = localtime(&t);

	static char t_str[16];
	strftime(t_str, 16, "%Y%m%d_%H%M%S", tmp);
	return t_str;
}
void cleanup() {
	printf("|%s| - [SERVER] Clearing up returned %d\n", calctime(), remove(SERVER));
	exit(EXIT_SUCCESS);
}

void exit_handler(int s){
	cleanup();
	// TODO send disconnect message to all clients
}

int get_client_index(struct sockaddr_un *clients, int len, char *buffer) {
	char * tmp_buf = malloc(200);
	int res = 1;

	snprintf(tmp_buf, 200, "%s%s", CLIENT, buffer + 1);
	
	char *closing_bracket = strchr(tmp_buf, ']');
	if (closing_bracket) 
		closing_bracket[0]  = '\0';
	for (int i = 0; i < len; i++) {
		res = strcmp(tmp_buf, clients[i].sun_path);
		if(!res) return i+1;
	}
	
	free(tmp_buf);
	return 0;
}

int main (int argc, char* argv[]) {

	if (argc < 2) {
		printf("|%s| - [ERROR] Please enter client number %s <NUMBER>\n", calctime(), argv[0]);
		exit (EXIT_FAILURE);
	} else if (argc > 2) {
		printf("|%s| - [ERROR] Too many arguments submitted\n", calctime());
	}
	signal (SIGINT, exit_handler);
		
	const int n_clients = atoi(argv[1]);
	printf("|%s| - [SERVER] %d-clients server started\n", calctime(), n_clients);
	int sock;
	ssize_t nbytes;

	// Client list, server and rejected client sockets
	struct sockaddr_un address = {
		.sun_family = AF_LOCAL,
		.sun_path = SERVER
	};
	socklen_t addrlen = sizeof(address);\

	struct sockaddr_un *clients = calloc(sizeof(struct sockaddr_un), n_clients);
	socklen_t *clientlen = calloc(sizeof(socklen_t), n_clients);

	for(int i = 0; i < n_clients;i++) clientlen[i] = sizeof(clients[i]);
	// fd sets for select

	sock = socket (AF_LOCAL, SOCK_DGRAM, 0);

	// Unlink socket file before creating a new on, else fail
	unlink(SERVER);

	
	if ( bind(sock, (struct sockaddr *) &address, addrlen) != 0) {
		printf("|%s| - [ERROR] Socket port in use, cant bind\n",calctime());
		cleanup();
	} 
	printf("|%s| - [SERVER] Binding to socket file succeeded %s\n", calctime(), address.sun_path);

	// Set the permissions of the server to 666 so everybody can read and write to it
	char mode[] ="0777";
	int mod;
	mod = strtol(mode,0,8);
	int retval;
	retval = chmod(SERVER,mod);
	if(retval < 0) {
    		printf("|%s| - [ERROR] A problem occured setting the socket permissions correctly: %d\n", calctime(), retval);
    		cleanup();
	}
	printf("|%s| - [SERVER] Setting permissions for socket file to %s\n", calctime(), mode);

	char *buffer = malloc(BUFFER);
	/* TODO: start receival and message ping in extra thread, so the console still works
	 * this is nice for kicking clients server side oder sending messages to all clients */
	while (1) {
		nbytes = recv(sock, buffer, BUFFER, 0);
		
		if (nbytes < 0) {
		  exit (EXIT_FAILURE);
		}

		buffer[nbytes] = '\0';
		printf ("|%s| - [SERVER] Got message: \"%s\", length = %zd\n", calctime(), buffer, nbytes);
		if (buffer[0] == '#') {
			char *cli = malloc (100);
			snprintf(cli, 100, "%s", buffer+1);

			printf("|%s| - [SERVER] New client [%s] registering...\n", calctime(), cli);

			// client is already registred TOFIX: other chat windows dies
			if (get_client_index(clients, n_clients, buffer)) continue;

			for (int i = 0; i < n_clients; i++) {
				if (clients[i].sun_family != AF_LOCAL) {
					printf("|%s| - [SERVER] Empty slot for client available at index %d\n", calctime(), i);
					clients[i].sun_family = AF_LOCAL;
					snprintf(
						clients[i].sun_path,
						sizeof(clients[i].sun_path),
						"%s%s",
						CLIENT,
						cli
					);
					const char *connected = "[SERVER] Successfully registered to the server";
					
					sendto(
						sock, 
						connected, 
						strlen(connected), 
						0, 
						(struct sockaddr *)&clients[i], 
						sizeof(clients[i])
						);
					
					for(int j = 0; j < n_clients; j ++ ) {
						if (j == i) continue;
						
						char *joined = malloc(strlen("[SERVER] \"") + strlen(cli) + strlen("\" joined the server") + 1);
						strcpy(joined, "[SERVER] \"");
						strcat(joined, cli);
						strcat(joined, "\" joined the server");
						sendto(
							sock, 
							joined, 
							strlen(joined), 
							0, 
							(struct sockaddr*)&clients[j], 
							clientlen[j]
							);
						free(joined);
						
					}
					printf("|%s| - [SERVER] Client socket %s succesfully registered to the server\n",calctime(), cli);
					break;
				} else {
					printf("|%s| - [SERVER] Registered client nr. %d is at address %s | %d\n", calctime(), i,clients[i].sun_path, AF_LOCAL);
				}
			}
			/* TODO: Sent reject message to rejected clients */
			free(cli);
		} else if (buffer[0] == DISC_CHAR) {
			int pos = get_client_index(clients, n_clients, buffer);
			if(!pos) {
				printf("|%s| - [SERVER] Unregistred client tried to disconnect\n", calctime());
				continue;
			}
			printf("|%s| - [SERVER] Client %s successfully disconnected\n", calctime(), clients[pos-1].sun_path);
			/* Set family to unspecified and the path to to \0 if a client disconnects"  */
			clients[pos-1].sun_family = AF_UNSPEC;
			clients[pos-1].sun_path[0] = '\0';
			/* Send disconnect message to every user */
			for(int j = 0; j < n_clients; j++) {
				if (clients[j].sun_family != AF_LOCAL)
					continue;
				
				ssize_t stlen = strlen("[SERVER] \"") + strlen(clients[pos-1].sun_path) - strlen(CLIENT) + strlen("\" disconnected from the server") + 1;
				char *disc = malloc(stlen);
				snprintf(
					disc, 
					stlen, 
					"%s%s",
					"[SERVER] \"",
					clients[pos-1].sun_path + strlen(CLIENT)
					
					);
				strcat(disc,"\" disconnected from the server");
				sendto(
					sock, 
					disc, 
					strlen(disc), 
					0, 
					(struct sockaddr*)&clients[j], 
					clientlen[j]
					);
				free(disc);
			}
		} else {
			if (!get_client_index(clients, n_clients, buffer)) continue;
           		
			printf("|%s| - [SERVER] Chat Message: \"%s\"\n", calctime(), buffer);
			
			if (strlen(buffer)) {
				for (int i = 0; i < n_clients; i++) {
					if (clients[i].sun_family != AF_LOCAL)
						continue;
					sendto(
						sock, 
						buffer, 
						strlen(buffer), 
						0, 
						(struct sockaddr*)&clients[i], 
						clientlen[i]
						);
					printf("|%s| - [SERVER] Sending message to %d of %d possible clients. Target socket: %s: Message \"%s\"\n", calctime(), i+1, n_clients, clients[i].sun_path, buffer);
				}
			}
		}
	}
	close (sock);
	cleanup();
	return 0;
}

