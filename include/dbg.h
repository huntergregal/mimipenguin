#ifndef DBG_H
#define DBG_H

#include <stdio.h>
#include <errno.h>
#include <string.h>
#define RESET   "\033[0m"
//#define RED     "\033[31m"  
//#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
//#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
//#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
//#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

#define clean_errno() (errno == 0 ? "None": strerror(errno))


#ifdef DEBUG
#define debug(M, ...) fprintf(stderr,"[" BOLDBLUE "DEBUG" RESET "]" "%s:%d:" M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define log_error(M, ...) fprintf(stderr, "[" BOLDRED "ERROR" RESET "]" "(%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)
#define log_warn(M, ...) fprintf(stderr, "[" BOLDYELLOW "WARN" RESET "]" "(%s:%d: errno:%s) " M "\n", __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)
#define log_info(M, ...) fprintf(stderr, "[" BOLDWHITE "INFO" RESET "]" "(%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
  
#else
#define debug(M, ...)
#define log_error(M, ...)
#define log_warn(M, ...)
#define log_info(M, ...)
#endif
 
#endif
