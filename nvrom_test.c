#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "cuckoo_filter.h"

int main(int argc, char **argv)
{       
        
        uint64_t size =10000;   
        uint8_t value[20];   //URI or EID
        app_cuckoo_hash_t keys;
        struct app_cuckoo table[10];
        struct app_cuckoo* t;
        memset(value, 0, sizeof(value));

        int socketid = 2;
        int  i;
        /* Initialization */
        t = (struct app_cuckoo *)app_cuckoo_alloc(table, socketid, size);   
        printf("Initialization end==============================================\n");
 
        struct timeval time;
        /* Insert */
        int insert_num = size;
        uint32_t insert_value = 0;
        int success =0;

        gettimeofday(&time,NULL);
        printf("%ld ms\n",time.tv_sec*1000+time.tv_usec/1000);

        
        for (i = 0; i < insert_num; i++) {
                
                insert_value = i;
                memcpy(value, &insert_value, sizeof(insert_value));   
                keys = app_cuckoo_hash(value, sizeof(value));         
                if(app_cuckoo_add(t, keys)==0)
                {
                        success++;
                }         
        } 
        printf("insert_num is %d\nsuccess num is %d\n\n",i,success);
        
        /* Lookup */
        success =0;
        for (i = 0; i < insert_num; i++) {
                
                insert_value = i+insert_num;
                memcpy(value, &insert_value, sizeof(insert_value));   
                keys = app_cuckoo_hash(value, sizeof(value));         
                if(app_cuckoo_chk(t, keys)==0)
                {
                        success++;
                }    
        } 

        printf("Lookup num is%d\nsuccess num is %d\n\n",i,success);
        app_cuckoo_free(t);    
        return 0;
}
