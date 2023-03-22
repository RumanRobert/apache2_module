#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_hash.h>
#include <apr_time.h>
#include <time.h>
#include <stdio.h>
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <apr.h>
#include <apr_pools.h>


module AP_MODULE_DECLARE_DATA apache20_module;


#define MAX_HITS        1  //Maximum number of times a user can connect within an interval without being blocked
#define INTERVAL        10
#define BLOCKING_PERIOD 10

static int blocking_period = BLOCKING_PERIOD;
static int maximum_hits = MAX_HITS; 
static int interval = INTERVAL;

struct requester{
    char ip[21];
    time_t timestamp;
    long count;
};

struct requester *hits[3097];  //Number of times the user connected to the server


const char *whitelisted_addresses[][15] = {"8.8.8.8"};


static void register_hooks(apr_pool_t *p);
static int access_checker(request_rec *r);
void insert(char ip[], time_t timestamp);
struct requester *create(long size, apr_pool_t *pool);
int is_whitelisted(char ip[]);
struct requester *find_user(const char *ip);


static int access_checker(request_rec *r)
{   // popis funkce 
    struct requester *user = NULL;
    time_t t = time(NULL);
    int ret = OK;

    ap_log_rerror(APLOG_MARK, APLOG_ERR,0,r,"debug: %s",r->connection->local_ip);

    if(is_whitelisted(r->connection->client_ip))    //Checking if the user is whitelisted, IF yes, without any controlling, the user gains access
        return OK;

    user = find_user(r->connection->client_ip);

    if(user!=NULL && t-user->timestamp<blocking_period){    //Looking for the user in the blacklisted addresses, IF found AND the blocking period did not expire, deny access
        user->timestamp = time(NULL);
        return HTTP_FORBIDDEN;
    }
    else{
        //user = find_user(r->connection->client_ip);
        
        if(user!=NULL)
        {
            if(t-user->timestamp<interval && user->count>=maximum_hits){    //check amount of hits within an interval
                ret = HTTP_FORBIDDEN;
            }
            else{
                if(t-user->timestamp>=interval)
                    user->count=0;
            }
            user->timestamp = t;
            user->count++;
        }
        else{
            insert(r->connection->client_ip, t);
        }
    }
    if(ret==HTTP_FORBIDDEN ){
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,"client denied by server configuration: %s",r->filename);
    }
    return ret;
}

void insert(char ip[], time_t timestamp){   
    //inserting the user into the blacklisted addresses
    apr_pool_t *pool;
    struct requester *r = (struct requester *)apr_pcalloc(pool, sizeof(struct requester)); // Allocate memory for the new requester struct
    strcpy(r->ip, ip);
    r->timestamp = timestamp;
    r->count = 1;
    for(int i=0;i<sizeof(hits);i++)
    {
        if(hits[i]==NULL)
            hits[i]=r;
            return;
    }
    return;
}

struct requester *find_user(const char *ip){ 
    //searching for a user in access list
    struct requester *temp_user= NULL;
     for(int i=0;i<sizeof(hits); i++)
    {
            if(hits[i]!=NULL && strcmp(hits[i]->ip,ip)){
                 temp_user = hits[i];
                return temp_user;
            }
    }
    return temp_user;
}

int is_whitelisted(char ip[]){  
    //checking if the user is part of the whitelisted addresses
    char investigated_ip[15];
    strcpy(investigated_ip,ip);
    for(int i=0;i<sizeof(whitelisted_addresses);i++)
    {
        if(strcmp(investigated_ip, *whitelisted_addresses[i]))
            return 1;
    }
    return 0;
}

struct requester *create(long size, apr_pool_t *pool){
    long i = 0;
    apr_pool_t *p;
    struct requester *user = (struct requester *)apr_pcalloc(p,sizeof(struct requester));

    if(user == NULL){
        return NULL;
    }
    return user;
}


static apr_status_t destroy_list(void *not_used){
    clear_mem(hits);
}

int clear_mem(struct requester **hits){
    free(hits);
    return 0;
}

static void register_hooks(apr_pool_t *p){
    ap_hook_access_checker(access_checker,NULL,NULL,APR_HOOK_MIDDLE);
    apr_pool_cleanup_register(p,NULL,apr_pool_cleanup_null, destroy_list);
}


module AP_MODULE_DECLARE_DATA apache2_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks
};



