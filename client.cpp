#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstring>
const static size_t max_msg_size = 4096;
static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}
static int32_t read_all(int fd, char* buffer, size_t n){
    while(n>0){
        size_t number_of_bytes_read = read(fd,buffer,n);
        if(number_of_bytes_read<=0){
            return -1;
        }
        n -= number_of_bytes_read;
        buffer += number_of_bytes_read;
    }
    return 0;
}
static int32_t write_all(int fd, char* buffer, size_t n){
    while(n>0){
        size_t number_of_bytes_written = write(fd,buffer,n);
        if(number_of_bytes_written<=0){
            return -1;
        }
        n -= number_of_bytes_written;
        buffer += number_of_bytes_written;
    }
    return 0;
}
static int32_t query(int fd, const char* msg){
    uint32_t length = (uint32_t)strlen(msg);
    char write_buffer[4+length];
    memcpy(write_buffer,&length,4);
    memcpy(&write_buffer[4],msg,length);
    int32_t write_error = write_all(fd,write_buffer,4+length);
    if(write_error){
        return write_error;
    }
    char read_buffer[4+max_msg_size];
    int32_t read_err = read_all(fd,read_buffer,4);
    memcpy(&length,read_buffer,4);
    if(length > max_msg_size){
        return -2;
    }
    read_err = read_all(fd,&read_buffer[4],length);
    if(read_err){
        return read_err;
    }
    printf("server says: %.*s\n", length, &read_buffer[4]);
    return 0;
}
int main(){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    int reuse_val = 1;
    int sockoptconfig = setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&reuse_val,sizeof(reuse_val));
    struct sockaddr_in client_address = {};
    client_address.sin_family = AF_INET;
    client_address.sin_port = ntohs(1234);
    client_address.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);
    int rv = connect(fd, (const struct sockaddr *)&client_address, sizeof(client_address));
    if (rv) {
        die("connect");
    }
    int32_t err1 = query(fd,"hello1");
    int32_t err2 = query(fd,"hello2");
    close(fd);
    return 0;
}