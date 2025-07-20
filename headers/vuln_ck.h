#include <curl/curl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

size_t write_callback(void *content,size_t size,size_t content_size,void *data_store){
  strncat((char *)data_store,(char *)content,size * content_size);
  return size * content_size;
}


int is_vulnable(char *url){

  CURL * curl;
  CURLcode result;
  FILE * payloads = NULL;
  FILE * error_lines = NULL;
  char payload[100];
  char error_line[100];
  bool found = false;


  printf("[*] Looking for vulnbelity\n");

  payloads = fopen("/home/artix/coding/project/sqlsploite/data/payloads/pyld_error.txt","r");
  if (!payloads) {
    printf("Failed to open payloads file\n");
    return 1;
  }

  error_lines = fopen("/home/artix/coding/project/sqlsploite/data/error_msgs.txt","r");
  if (!error_lines) {
    printf("Failed to open error ditector file\n");
    return 1;
  }

  while((fgets(payload,sizeof(payload),payloads)) != NULL) {
    char response[100000] = {'\0'};
    if (found) break;

    payload[strcspn(payload,"\n")] = '\0';
    char full_url[2048];
    snprintf(full_url, sizeof(full_url), "%s%s", url, payload);

    curl = curl_easy_init();

    if (!curl) {
      printf("Failed to init curl\n");
      return 1;
    }

    curl_easy_setopt(curl,CURLOPT_URL,&full_url);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,write_callback);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,response);

    result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (result != CURLE_OK) {
      fprintf(stderr, "[-] Failed to make HTTP request: %s\n", curl_easy_strerror(result));
      return 1;
    }

    while ((fgets(error_line,sizeof(error_line),error_lines)) != NULL) {
      error_line[strcspn(error_line,"\n")] = '\0';
      if (strstr(response,error_line)) {
        found = true;
        break;
      }
    }

  }

  fclose(payloads);
  fclose(error_lines);
  if (found == true) {
    printf("✅️ Seeme like vulnable\n");
  }else {
    printf("❌️ Not vulnable\n");
    return 1;
  }
  return 0;
}
