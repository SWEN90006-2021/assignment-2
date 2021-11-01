/**
 *
 * A FotBot looks like a wristwatch and includes functions for
 * counting the steps of the wearer. This data is uploaded into a
 * cloud-based system. The FotBot and its cloud application has three
 * main intended features:
 *  - To record the number of steps a person takes each day.
 *  - To share information with other FotBot wearers for social
 *    reasons; e.g.competitions to see who can take the most steps.
 *  - To share information with the FotBot company.
 *
 * Each FotBot's data is stored in the cloud. User data is accessible 
 * the user themselves, their friends in the friend list or the admin account
 *
 * The server code is below. For simplicity for the assignment, the
 * database is implemented as an internal HashMap data structure.
 *
 * ACKNOWLEDGEMENT:
 * The server code is written based on this C socket server example
 * https://www.binarytides.com/server-client-example-c-sockets-linux/
 *
 * We also use code from the LightFTP project (https://github.com/hfiref0x/LightFTP)
 * with some modifications
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include "fotbot.h"

#define INVALID_SOCKET         -1
#define CLIENT_REQUEST_MAX_SIZE 2000
#define CMD_QUIT                8

//Define a "lookup" table for all command-handling functions
static const FUNCTION_ENTRY fbprocs[MAX_CMDS] = {
  {"USER", fbUSER}, {"PASS", fbPASS}, {"REGU", fbREGU}, {"UPDA",  fbUPDA},
  {"ADDF", fbADDF}, {"GETS", fbGETS}, {"GETF", fbGETF}, {"LOGO", fbLOGO},
  {"QUIT", fbQUIT}
};

//Global variables
int client_sock;      /* accepted client socket */
khash_t(hmu) *users;  /* a hash map containing all user information */
khint_t ki;           /* a hash iterator */
int fb_state = INIT, discard;
char* active_user_name = NULL;


/*** Network handling functions ***/

/**
  * Read a command sent from the client.
  * Each command ends with two special characters "\r\n"
  *
  * @in     sockfd        socket from which command is read
  * @in-out buffer        a buffer storing the command
  * @in     buffer size   buffer size
  */
int recvcmd(int sockfd, char *buffer, size_t buffer_size) {
  ssize_t	bytes_received, pointer = 0;

  memset(buffer, 0, buffer_size);
  --buffer_size;

  while (buffer_size > 0) {
    bytes_received = recv(sockfd, buffer + pointer, buffer_size, 0);

    if (bytes_received <= 0)
      return bytes_received;

    buffer_size -= bytes_received;
    pointer += bytes_received;

    //Check for the command terminator ("\r\n")
    if (pointer >= 2) {
      if ((buffer[pointer-2] == '\r') && (buffer[pointer-1] == '\n')) {
        buffer[pointer-2] = 0;
        return 1;
      }
    }
  }
  return 0;
}

/**
  * Send a response to the client
  *
  * @in sockfd        socket to which response is sent
  * @in response      response to be sent
  */
ssize_t sendResponse(const int sockfd, const char *response)
{
	size_t len = strlen(response);
	return (send(sockfd, response, len, MSG_NOSIGNAL) >= 0);
}

/*** Helper functions ***/

/**
  * Split a string using a delimiter
  *
  * @in str       socket to which response is sent
  * @in delim     a delimiter (e.g., a comma)
  * @in count     number of tokens after splitting
  */
char** strSplit(char* str, const char* delim, int *count)
{
  char** tokens = NULL;
  char *token;
  *count = 0;

  /* get the first token */
  char* tmp = strdup(str);
  token = strtok(tmp, delim);

  /* walk through other tokens */
  while (token != NULL)
  {
    tokens = (char**) realloc(tokens, sizeof(char*) * (*count + 1));
    tokens[*count] = strdup(token);
    *count = *count + 1;
    token = strtok(NULL, delim);
  }

  free(token);
  free(tmp);
  return tokens;
}

/**
  * Create a new user_info_t object
  * to store user-specific information (e.g., password, steps, friends)
  */
user_info_t *newUser() {
  user_info_t *user = (user_info_t *) malloc(sizeof(user_info_t));
  user->password = NULL;
  user->friends = NULL;
  user->friend_count = 0;
  user->steps = NULL;
  user->step_count = 0;
  return user;
}

/**
  * Check if a username exists
  */
int isUser(const char* name) {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      if (!strcmp(kh_key(users,ki), name)) return 1;
    }
  }
  return 0;
}

/**
  * Check if the given password is correct
  */
int isPasswordCorrect(const char* password) {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      if (!strcmp(kh_value(users,ki)->password, password) ||
          !strcmp(kh_key(users,ki), active_user_name))
      return 1;
    }
  }
  return 0;
}

/**
  * Get an iterator pointint to a user
  */
khint_t getUser(const char* name) {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      if (!strcmp(kh_key(users,ki), name)) return ki;
    }
  }
  return kh_end(users);
}

/**
  * Check if a user is a friend of the current active user
  */
int isFriend(const char* name) {
  ki = getUser(name);
  user_info_t *user = kh_value(users, ki);
  for (int i = 0; i < user->friend_count; i++) {
    if (!strcmp(user->friends[i], active_user_name)) return 1;
  }
  return 0;
}

/**
  * Free up memory used to store all users
  */
void freeUsers() {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      user_info_t *user = kh_value(users, ki);
      free(user->steps);
      for (int i = 0; i < user->friend_count; i++) {
        free(user->friends[i]);
      }
      free(user->friends);
      free(user);
    }
  }
  kh_destroy(hmu, users);

  free(active_user_name);
}

/**
  * Free up a string array
  */
void freeTokens(char **tokens, int count) {
  for (int i = 0; i < count; i++) {
    free(tokens[i]);
  }
  free(tokens);
}

/*** Command-handling functions ***/

/**
  * Handle user login
  */
int fbUSER(char *params) {
  if (fb_state == INIT) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //Check if the user exits
    if (!isUser(params)) {
      return sendResponse(client_sock, error400);
    } else {
      sendResponse(client_sock, success210);
      //Update the current active user name
      free(active_user_name);
      active_user_name = strdup(params);
      //Update server state
      fb_state = USER_OK;
    }
  } else {
    return sendResponse(client_sock, error530);
  }

  return 0;
}

/**
  * Handle user login
  */
int fbPASS(char *params) {
  if (fb_state == USER_OK) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    if (!isPasswordCorrect(params)) {
      return sendResponse(client_sock, error410);
    } else {
      sendResponse(client_sock, success220);
      //Update server state
      fb_state = LOGIN_SUCCESS;
    }
  } else {
    return sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle REGU-Register new user command
  */
int fbREGU(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    if (strcmp(active_user_name, "admin")) {
      return sendResponse(client_sock, error430);
    }

    //This command expects two arguments/parameters
    //(username and password) seperated by a comma
    //e.g. REGU newuser,newpassword
    char **tokens = NULL;
    int count = 0;
    tokens = strSplit(params, ",", &count);

    if (count == 2) {
      user_info_t *user = newUser();
      user->password = tokens[1];

      ki = kh_put(hmu, users, strdup(tokens[0]), &discard);
      kh_value(users, ki) = user;
      sendResponse(client_sock, success230);
    } else {
      sendResponse(client_sock, error520);
    }

    freeTokens(tokens, count);
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle UPDA-Insert user's steps
  */
int fbUPDA(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //This command expects a list of positive integer numbers
    //seperated by commas (e.g., UPDA 100, 0, 200, 3000)
    char **tokens = NULL;
    int count = 0;
    tokens = strSplit(params, ",", &count);

    if (count > 0) {
      int *tmpSteps = (int *) malloc(sizeof(int) * count);
      for (int i = 0; i < count; i++) {
        int step = atoi(tokens[i]);

        //Check for invalid step count
        if (((step == 0) && (strcmp(tokens[i],"0"))) || step < 0) {
          free(tmpSteps);
          freeTokens(tokens, count);
          return sendResponse(client_sock, error520);
        } else {
          tmpSteps[i] = step;
        }
      }

      //Appending numbers to the steps list
      khint_t k = getUser(active_user_name);
      user_info_t *user = kh_value(users, k);
      user->steps = (int *) realloc(user->steps, sizeof(int) * (user->step_count + count));
      memcpy(&user->steps[user->step_count], tmpSteps, count * sizeof(int));
      user->step_count += count;

      //free up temporary memory
      free(tmpSteps);
      freeTokens(tokens, count);
      sendResponse(client_sock, success240);
    } else {
      return sendResponse(client_sock, error520);
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle ADDF-Add a friend
  */
int fbADDF(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //This command expects an existing username
    khint_t k = getUser(params);

    if (k == kh_end(users)) {
      return sendResponse(client_sock, error400);
    } else {
      k = getUser(active_user_name);
      user_info_t *user = kh_value(users, k);

      user->friends = (char**) realloc(user->friends, sizeof(char*) * (user->friend_count + 1));
      user->friends[user->friend_count] = strdup(params);
      user->friend_count++;

      sendResponse(client_sock, success250);
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle GETS-Get step data
  */
int fbGETS(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //This command expects only one argument
    //which is the username of the user whose steps are being collected
    khint_t k = getUser(params);

    if (k == kh_end(users)) {
      return sendResponse(client_sock, error400);
    } else {

      //Make sure the current user has a permission to
      //read step data of the given user
      if (strcmp(active_user_name, "admin") &&
          strcmp(active_user_name, params)) {
        if (!isFriend(params)) {
          return sendResponse(client_sock, error430);
        }
      }

      user_info_t *user = kh_value(users, k);

      if (user->step_count > 0) {
        sendResponse(client_sock, successcode);
        sendResponse(client_sock, " Steps: ");
        for (int i = 0; i < user->step_count; i++) {
          char tmpStepStr[MAX_NUMBER_LENGTH];
          sprintf(tmpStepStr, "%d", user->steps[i]);
          sendResponse(client_sock, tmpStepStr);
          if (i != user->step_count - 1) sendResponse(client_sock, ",");
        }
        sendResponse(client_sock, "\r\n");
      } else {
        sendResponse(client_sock, error420);
      }
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle GETF-Get all friends of the current active user
  */
int fbGETF(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    //This command expects no arguments
    khint_t k = getUser(active_user_name);
    user_info_t *user = kh_value(users, k);

    if (user->friend_count > 0) {
      sendResponse(client_sock, successcode);
      sendResponse(client_sock, " Friends: ");
      for (int i = 0; i < user->friend_count; i++) {
        sendResponse(client_sock, user->friends[i]);
        if (i != user->friend_count - 1) sendResponse(client_sock, ",");
      }
      sendResponse(client_sock, "\r\n");
    } else {
      sendResponse(client_sock, error420);
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle LOGO-Log out
  */
int fbLOGO(char *params) {
  if (fb_state == LOGIN_SUCCESS) {
    //This command expects no arguments
    sendResponse(client_sock, success260);
    fb_state = INIT;
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle QUIT-Terminate the server
  */
int fbQUIT(char *params) {
  //This command expects no arguments
  sendResponse(client_sock, success270);
  return 0;
}

/**
  * main function
  * It expects to take two arguments
  * arg_1: an IP address on which the server is running (e.g., 127.0.0.1)
  * arg_2: a port to which the server is listening (e.g., 8888)
  * Example command: ./fotbot 127.0.0.1 8888
  *
  */

int main(int argc , char *argv[]) {
  int socket_desc, addrlen, read_size;
  struct sockaddr_in server, client;
  char rcvbuf[CLIENT_REQUEST_MAX_SIZE];
  int exit_code = 0;

  //Initialize the "database"
  users = kh_init(hmu);

  //Check the number of arguments
  if (argc < 3) {
    fprintf(stderr, "[ERROR] FotBot requires two arguments: an IP address and a port number\n");
    fprintf(stderr, "[ERROR] Run fotbot on localhost and listen to port 8888: ./fotbot 127.0.0.1 8888\n");
    exit_code = 1;
    goto exit;
  }

  //Add a default admin user

  user_info_t *admin = newUser();
  admin->password = strdup("admin");

  ki = kh_put(hmu, users, "admin", &discard);
  kh_value(users, ki) = admin;

  //Create a TCP socket
  socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc == -1) {
    fprintf(stderr, "[ERROR] FotBot: cannot create a socket\n");
    exit_code = 1;
    goto exit;
  }

  //Enable reusing of local addresses
  const int trueFlag = 1;
  if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)) < 0) {
    fprintf(stderr, "[ERROR] FotBot: cannot set a socket option\n");
    exit_code = 1;
    goto exit;
  }

  //Prepare a sockaddr_in structure for the server
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(argv[1]);
  server.sin_port = htons(atoi(argv[2]));

  //Bind a socket to the server
  if(bind(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0) {
    fprintf(stderr, "[ERROR] FotBot: bind failed. error code is %d\n", errno);
    exit_code = 1;
    goto exit;
  }

  //Listen to incoming connection request
  fprintf(stdout, "FotBot: waiting for an incoming connection ...\n");

  //For simplicity, this server accepts only one connection
  listen(socket_desc, 1);
  addrlen = sizeof(struct sockaddr_in);

  client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&addrlen);
  if (client_sock < 0) {
    fprintf(stderr, "[ERROR] FotBot fails to accept an incoming connection\n");
    exit_code = 1;
    goto exit;
  }

  fprintf(stdout, "FotBot: connection accepted\n");

  int i, j, cmdlen, cmdno, rv;
  char *cmd = NULL, *params = NULL;
  //Receive requests from client
  while (socket_desc != INVALID_SOCKET) {
    read_size = recvcmd(client_sock, rcvbuf, CLIENT_REQUEST_MAX_SIZE);
    if (read_size <= 0) break;
    fprintf(stdout,"FotBot: receiving %s\n", rcvbuf);

    //Identify the command
    i = 0;
    while ((rcvbuf[i] != 0) && (isalpha(rcvbuf[i]) == 0)) ++i;

    cmd = &rcvbuf[i];
    while ((rcvbuf[i] != 0) && (rcvbuf[i] != ' ')) ++i;

    //Skip space characters between command & parameters
    cmdlen = &rcvbuf[i] - cmd;
    while (rcvbuf[i] == ' ') ++i;

    //Get parameters
    if (rcvbuf[i] == 0) params = NULL;
    else params = &rcvbuf[i];

    cmdno = -1; //command number
    rv = 1;     //value returned from the command handling function

    for (j = 0; j < MAX_CMDS; j++) {
      if (strncasecmp(cmd, fbprocs[j].name, cmdlen) == 0) {
        //The given command is supported
        cmdno = j;
        rv = fbprocs[j].proc(params); //call corresponding command-handling function
        break;
      }
    }

    //The given command is *not* supported
    if (cmdno == -1) {
      sendResponse(client_sock, error500);
    }

    if (cmdno == CMD_QUIT) {
      goto exit;
    }
  }

  if(read_size == 0) {
    fprintf(stdout, "FotBot: client disconnected\n");
  } else if(read_size == -1) {
    fprintf(stderr, "[ERROR] FotBot fails to receive client requests\n");
    exit_code = 1;
    goto exit;
  }

exit:
  //free up memory
  freeUsers();
  return exit_code;
}
