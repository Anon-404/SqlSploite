#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <stdlib.h>

// my own headerr 
#include "headers/vuln_ck.h"

struct InjectionOptions {
    char url[1024];
    char param[128];
    char cookie[1024];
    char header[1024];
    int crawl_level;

    char dbs[128];
    char table[128];
    char columns[512];
};
struct InjectionOptions inject = {0};

bool url_parser(char * tmp_url){
  CURLU * url;
  char *scheme = NULL, *hostname = NULL, *query = NULL;

  url = curl_url();
  if (!url) {
    fprintf(stderr, "Error: failed to init CURLU\n");
    return false;
  }
  CURLUcode rc = curl_url_set(url,CURLUPART_URL,tmp_url,0);
  if (rc != CURLUE_OK) {
    fprintf(stderr, "Error: %s\n", curl_url_strerror(rc));
    curl_url_cleanup(url);
    return false;
  }

  curl_url_get(url,CURLUPART_SCHEME,&scheme,0);
  curl_url_get(url,CURLUPART_HOST,&hostname,0);
  curl_url_get(url,CURLUPART_QUERY,&query,0);

  if (scheme == NULL) {
    printf("Invalid url: scheme required: http,http\n");
    curl_url_cleanup(url);
    return false;
  } else if (hostname == NULL) {
    printf("Invalid url: No hostname\n");
    curl_url_cleanup(url);
    return false;
  } else if (query == NULL) {
    printf("No query provided\nUse: set CRAWL [1-5] to auto crawl");
  } else {
    strcpy(inject.param,query);
    is_vulnable(tmp_url);
  }

  curl_free(scheme);
  curl_free(hostname);
  curl_free(query);
  curl_url_cleanup(url);

  strcpy(inject.url,tmp_url);

  return true;
}

void help() {
    printf("\nAvailable Commands:\n");
    printf("  help                      : Show this help menu\n");
    printf("  options                   : Show all currently set values (URL, PARAM, COOKIE, HEADER, etc.)\n");
    printf("  set URL [target URL]      : Set the target URL\n");
    printf("  set PARAM [param name]    : Set the parameter for SQL injection (if multiple)\n");
    printf("  set COOKIE [cookie]       : Set a custom cookie header\n");
    printf("  set HEADER [header]       : Set custom HTTP header (use multiple times for multiple headers, max 20)\n");
    printf("  set CRAWL [1-5]           : Enable crawler and set crawl level\n");
    printf("  set PROXY [path/proxy.txt]: Set a proxy list file to use (ip:port format)\n");
    printf("  use PROXY                 : Enable libcurl default proxy support (uses one from set list or global)\n");
    printf("  dump DBS                  : Dump available database names\n");
    printf("  set DBS [db name]         : Set target database for dumping\n");
    printf("  dump TABLES               : Dump tables from the selected database\n");
    printf("  set TABLE [table name]    : Set target table for dumping\n");
    printf("  dump COLUMNS              : Dump columns from the selected table\n");
    printf("  set COLUMN [columns]      : Set specific columns to dump\n");
    printf("  dump DATA                 : Dump data from selected table/columns\n");
    printf("  reset                     : Reset all set values (URL, PARAM, HEADER, etc.)\n");
    printf("  [bash command]            : Run a bash command (e.g. !ls, !whoami)\n");
    printf("  exit                      : Exit the tool\n");
}

void show_options() {
    printf("\n\x1b[36m[+] Current Options:\x1b[0m\n");
    printf("  \x1b[33mURL      \x1b[0m: %s\n", inject.url[0] ? inject.url : "(not set)");
    printf("  \x1b[33mPARAM    \x1b[0m: %s\n", inject.param[0] ? inject.param : "(not set)");
    printf("  \x1b[33mCOOKIE   \x1b[0m: %s\n", inject.cookie[0] ? inject.cookie : "(not set)");
    printf("  \x1b[33mHEADER   \x1b[0m: %s\n", inject.header[0] ? inject.header : "(not set)");
    printf("  \x1b[33mCRAWL    \x1b[0m: %s\n", inject.crawl_level ? (char[4]){inject.crawl_level + '0', '\0'} : "(not set)");
    printf("  \x1b[33mDBS      \x1b[0m: %s\n", inject.dbs[0] ? inject.dbs : "(not set)");
    printf("  \x1b[33mTABLE    \x1b[0m: %s\n", inject.table[0] ? inject.table : "(not set)");
    printf("  \x1b[33mCOLUMNS  \x1b[0m: %s\n", inject.columns[0] ? inject.columns : "(not set)");
}

int main()
{
  char cmd[1028];
  char tmp_url[1024];
  char set_val[100];

  printf("sqlsploit> Welcome to sqlsploit. type (help)\n");

  while (true) {
  
    printf("\nsqlsploit> ");
    fgets(cmd,sizeof(cmd),stdin);
    cmd[strcspn(cmd,"\n")] = '\0';

    if (strcmp(cmd,"help") == 0) {

      help();

    }else if (strncmp(cmd,"set ",4) ==0 ) {
      strcpy(set_val,cmd + 4);
      if (strstr(set_val,"URL")) {
        strcpy(tmp_url,cmd + 8);
        url_parser(tmp_url);

      }else if (strstr(set_val,"PARAM")) {
        strcpy(inject.param,cmd + 10);

      }else if (strstr(set_val,"COOKIE")) {
        strcpy(inject.cookie,cmd + 11);

      }else if (strstr(set_val,"HEADER") ) {
        strcpy(inject.header,cmd + 11);

      }else if (strstr(set_val,"CRAWL")) {
        inject.crawl_level = atoi(cmd + 10);

      }else if (strstr(set_val,"DBS")) {
        strcpy(inject.dbs,cmd + 8);

      }else if (strstr(set_val,"TABLE")) {
        strcpy(inject.table,cmd + 10);

      }else if (strstr(set_val,"COLUMNS")) {
        strcpy(inject.columns,cmd + 12);

      }else {
        printf("Invalid set option\n");
      }
    } else if (strcmp(cmd,"reset") == 0) {
      memset(&inject, 0, sizeof(inject));
      printf("[*] All options have been reset.\n");

    } else if (strcmp(cmd,"options") == 0) {
      show_options();
    }else if (strcmp(cmd,"exit") == 0) {

      printf("Exiting.....\n");
      return 0;

    }else {
      if(system(cmd) != 0){
        printf("Unknown command\n");
      }
    }

  }

  return 0;
}
