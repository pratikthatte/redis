#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <cstring>
#include <vector>
const static size_t max_msg_size = 4096;
static std::map<std::string, std::string> cache_data;

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}
struct Conn {
    int fd = -1;
    bool want_read = false;
    bool want_write = false;
    bool want_close = false;
    std::vector<uint8_t> incoming_data;
    std::vector<uint8_t> outgoing_data;
};
struct Response{
    uint32_t status = 0;
    std::vector<uint8_t> data;
};
static void fd_set_nb(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}
static Conn* handle_accept(int fd){
    struct sockaddr_in client_addr = {};
    socklen_t client_len = sizeof(client_addr);
    int connection_fd = accept(fd,(struct sockaddr*)&client_addr,(socklen_t*)&client_len);
    if(connection_fd<0){
        return nullptr;
    }
    fd_set_nb(connection_fd);
    Conn* conn = new Conn();
    conn->fd = connection_fd;
    conn->want_read = true;
    return conn;
}
static bool try_one_request(Conn* conn){
    uint8_t read_buffer[64*1024];
    ssize_t number_of_bytes_read = read(conn->fd,read_buffer,sizeof(read_buffer));
    if(number_of_bytes_read<=0){
        conn->want_close = true;
        return false;
    }
    conn->incoming_data.insert(conn->incoming_data.end(),&read_buffer[0],&read_buffer[0]+number_of_bytes_read);
    if(conn->incoming_data.size()<4){
        return false;
    }
    size_t length = (size_t)conn->incoming_data.size();
    std::vector<std::string> command;
    if(!parse_request(&conn->incoming_data[0],conn,(size_t)length,command)){
        conn->want_close = true;
        return false;
    }
    Response response = process_request(command);
    add_response(response,conn->outgoing_data);
    return true;
}
static void add_response(Response& response, std::vector<uint8_t>& out){
    uint32_t response_length = 4 + response.data.size();
    out.append((const uint8_t *)&response_length,4);
    out.append((const uint8_t *)&response.status,4);
    out.append(response.data.data(),response.data.size());
}
static Response process_request(std::vector<std::string>& command){
    Response* response = new Response();
    if(command.size()==2 && command[0]=="get"){
        if(cache_data.find(command[1])==cache_data.end()){
            response.status = 1; //Data not available
        }
        else{
            response.status = cache_data[command[1]];
        }
    }
    else if(command.size()==3 && command[0]=="set"){
        cache_data[command[1]]=command[2];
    }
    else if(command.size()==2 && command[0]=="delete"){
        cache_data.erase[command[1]];
    }
    else{
        response.status = 2; //Invalid command
    }
    return response;
}
static bool parse_request(uint8_t* data_start, size_t length, std::vector<std::string>& command){
    const uint8_t* data_end = data_start+length;
    uint32_t number_of_strings;
    if(!read_32(data_start,data_end,number_of_strings)){
        return false;
    }
    while(command.size() < number_of_strings){
        uint32_t temp_length;
        if(!read_32(data_start,data_end,temp_length)){
            return false;
        }
        command.push_back(std::string());
        if(!read_string(data_start,(size_t)temp_length,command.back())){
            return false;
        }
    }
    if(data_start!=data_end){
        return false;
    }
    return true;
}
static bool read_string(const uint8_t* data_start, const uint8_t* data_end, size_t length, std::string &result_string){
    if(data_start + length > data_end){
        return false;
    }
    result_string.assign(data_start,data_start + length);
    data_start += length;
    return true;
}
static bool read_32(uint8_t* data_start, uint8_t* data_end, uint32_t &number_of_strings){
    if(data_start+4 > data_end){
        return false;
    }
    memcpy(&number_of_strings,data_start,4);
    data_start += 4;
    return true;
}
static void handle_read(Conn* conn){
    while(try_one_request(conn)){
        if (conn->outgoing_data.size() > 0) {
            conn->want_read = false;
            conn->want_write = true;
        }
    }
}
static void handle_write(Conn* conn){
    ssize_t number_of_bytes_to_write = write(conn->fd, conn->outgoing_data.data(),(size_t)conn->outgoing_data.size());
    if(number_of_bytes_to_write<=0){
        conn->want_close = true;
        return;
    }
    conn->outgoing_data.erase(conn->outgoing_data.begin(),conn->outgoing_data.begin() + number_of_bytes_to_write);
    if (conn->outgoing_data.size() == 0) { 
        conn->want_read = true;
        conn->want_write = false;
    }
}

int main(){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    int reuse_val = 1;
    int sockoptconfig = setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&reuse_val,sizeof(reuse_val));
    struct sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(1234);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int bind_result = bind(fd,(struct sockaddr*)&address, sizeof(address));
    if(bind_result){
        die("bind()");
    }
    int listen_result = listen(fd,SOMAXCONN);
    if(listen_result){
        die("listen()");
    }
    std::vector<Conn*> fd_conn_mapping;
    std::vector<struct pollfd> poll_args;
    fd_set_nb(fd);
    while(true){
        poll_args.clear();
        struct pollfd temp_pollfd = {fd,POLLIN,0};
        poll_args.push_back(temp_pollfd);
        for(Conn* temp_conn : fd_conn_mapping){
            if(!temp_conn){
                continue;
            }
            struct pollfd temp_pfd_from_conn = {temp_conn->fd,POLLERR,0};
            if(temp_conn->want_read){
                temp_pfd_from_conn.events |= POLLIN;
            }
            if(temp_conn->want_write){
                temp_pfd_from_conn.events |= POLLOUT;
            }
            poll_args.push_back(temp_pfd_from_conn);
        }
        int poll_return_val = poll(poll_args.data(),(nfds_t)poll_args.size(),15000);
        if(poll_return_val<=0){
            die("poll()");
        }
        if(poll_args[0].revents){
            if(Conn* conn = handle_accept(poll_args[0].fd)){
                if(fd_conn_mapping.size() <= conn->fd){
                    fd_conn_mapping.resize(conn->fd+1);
                }
                fd_conn_mapping[conn->fd] = conn;
            }
        }
        for(int i=1;i<poll_args.size();i++){
            uint32_t temp_revents = poll_args[i].revents;
            Conn* conn = fd_conn_mapping[poll_args[i].fd];
            if(temp_revents & POLLIN){
                handle_read(conn);
            }
            if(temp_revents & POLLOUT){
                handle_write(conn);
            }
            if(temp_revents & POLLERR || conn->want_close){
                close(conn->fd);
                fd_conn_mapping[conn->fd] = nullptr;
                delete conn;
            }
        }
    }
    return 0;
}