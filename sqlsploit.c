#include <stdio.h>
#include <curl/curl.h>
#include <string.h>

size_t writecall(void*content,size_t size,size_t content_len,void*user_ptr){
  strncat((char*)user_ptr,(char*)content,size * content_len);
  return size * content_len;
}

int main(){

  FILE * file = NULL;
  CURL * curl = curl_easy_init();
  char url[258];
  char resp[100000];
  bool found = false;

  printf("Enter url: ");
  fgets(url,sizeof(url),stdin);
  url[strcspn(url,"\n")] = '\0';

  curl_easy_setopt(curl,CURLOPT_URL,url);
  curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,writecall);
  curl_easy_setopt(curl,CURLOPT_WRITEDATA,resp);
  CURLcode res;
  res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    printf("err\n");
    return 1;
  }
  char str[128];


  file = fopen("/home/artix/coding/c/error.txt","r");
  while ((fgets(str,sizeof(str),file))!= NULL) {
    str[strcspn(str, "\n")] = '\0';
    if (strstr(resp,str)){
      found = true;
      break;
    }
  }

  if (found) {
    printf("✅️ vuln found\n");
  }else{
    printf("❌️ not found\n");
  }

  fclose(file);
  return 0;
}
