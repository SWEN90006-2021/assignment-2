#ifndef FOTBOT_H_
#define FOTBOT_H_

#include "khash.h"
#include "klist.h"

typedef int (*FBROUTINE) (char* params);

typedef struct {
    const char* name;
    FBROUTINE   proc;
} FUNCTION_ENTRY;

#define FB_COMMAND(cmdname)    int cmdname(char* params)
#define MAX_CMDS               9
#define MAX_NUMBER_LENGTH      11

FB_COMMAND(fbUSER);
FB_COMMAND(fbPASS);
FB_COMMAND(fbREGU);
FB_COMMAND(fbUPDA);
FB_COMMAND(fbADDF);
FB_COMMAND(fbGETS);
FB_COMMAND(fbGETF);
FB_COMMAND(fbLOGO);
FB_COMMAND(fbQUIT);

#define successcode    "200"

#define success200     "200 Command okay.\r\n"
#define success210     "210 USER okay.\r\n"
#define success220     "220 User logged in, proceed.\r\n"
#define success230     "230 New user registered.\r\n"
#define success240     "240 Data updated.\r\n"
#define success250     "250 New friend added.\r\n"
#define success260     "260 Log out successfully.\r\n"
#define success270     "270 Goodbye!\r\n"

#define error400       "400 USER does not exist.\r\n"
#define error410       "410 PASS incorrect.\r\n"
#define error420       "420 Empty data.\r\n"
#define error430       "430 Permission denied.\r\n"

#define error500       "500 Syntax error, command unrecognized.\r\n"
#define error510       "510 Please login with USER and PASS.\r\n"
#define error520       "520 Syntax error, parameters in wrong format.\r\n"
#define error530       "530 This command is not allowed in current state.\r\n"

typedef struct {
  char* password;
  int* steps;
  int step_count;
  char** friends;
  int friend_count;
} user_info_t;

//define a hashmap type named hmu
//Key: string
//Value: object of user_info_t type
KHASH_INIT(hmu, kh_cstr_t, user_info_t*, 1, kh_str_hash_func, kh_str_hash_equal)

enum {
  /* 00 */ INIT,
  /* 01 */ USER_OK,
  /* 02 */ LOGIN_SUCCESS
};

#endif /* FOTBOT_H_ */
