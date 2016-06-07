#include <stdio.h>		// used for sprintf
#include <iostream>		// used for cout
#include <string.h>		// used for string
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define IPV4_ADDR_LENGTH 		4
#define IPV6_ADDR_LENGTH 		16


/**
    Converts an addreess from struct sockaddr to byte array.

    @param 	addr 	Address to convert.
    @param 	buffer 	Address to return.
    @param 	len 	Address length to return.
*/

void convertSockAddrToByteArray(const struct sockaddr *addr, unsigned char *buffer, size_t *len)
{
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		unsigned char *c_addr = (unsigned char *)&addr4->sin_addr.s_addr;
		memcpy(buffer, c_addr, IPV4_ADDR_LENGTH);
		*len = IPV4_ADDR_LENGTH;
	}
	else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
		memcpy(buffer, addr6->sin6_addr.s6_addr, IPV6_ADDR_LENGTH);
		*len = IPV6_ADDR_LENGTH;
	}
}

/**
    Converts an addreess from struct sockaddr to string in human readable format
    using inet_ntop

    @param 	addr 	Address to convert.
    @param 	buffer 	Address to return.
    @param 	size 	Address size to return.
*/

std::string convertSockAddrToStringNtop(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		char str[INET_ADDRSTRLEN];
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		inet_ntop(AF_INET, &addr4->sin_addr, str, INET_ADDRSTRLEN);
		return str;
	}
	else if (addr->sa_family == AF_INET6) {
		char str[INET6_ADDRSTRLEN];
		struct sockaddr_in6 *addr6=(struct sockaddr_in6 *)addr;
		inet_ntop(AF_INET6, &addr6->sin6_addr, str, INET6_ADDRSTRLEN);
		return str;
	}
	else {
		return "";
	}
}


/**
    Converts an addreess from struct sockaddr to string in human readable format
    @param 	addr 	Address to convert.
    @param 	buffer 	Address to return.
    @param 	size 	Address size to return.
*/

std::string convertSockAddrToString(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		char str[INET_ADDRSTRLEN];
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		unsigned char *ap = (unsigned char *)&addr4->sin_addr.s_addr;
		sprintf(str, "%d.%d.%d.%d",
	     ap[0], ap[1], ap[2], ap[3]);
		return str;
	}
	else if (addr->sa_family == AF_INET6) {
		char str[INET6_ADDRSTRLEN];
		struct sockaddr_in6 *addr6=(struct sockaddr_in6 *)addr;
		unsigned char *ap = (unsigned char *)&addr6->sin6_addr.s6_addr;
		sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 (int)ap[0], (int)ap[1], (int)ap[2], (int)ap[3],
                 (int)ap[4], (int)ap[5], (int)ap[6], (int)ap[7],
                 (int)ap[8], (int)ap[9], (int)ap[10], (int)ap[11],
                 (int)ap[12], (int)ap[13], (int)ap[14], (int)ap[15]);
		return str;
	}
	else {
		return "";
	}
}


/**
    Check and convert an Ipv4-mapped Ipv6 adress to plain Ipv4 

    @param 	addr 	Address to convert.
*/

void convertIpv4MappedIpv6ToIpv4(struct sockaddr_storage *addr) 
{
	if (addr->ss_family == AF_INET6) {
	    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
	    if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
	        struct sockaddr_in addr4;
	        memset(&addr4, 0, sizeof(addr4));
	        addr4.sin_family = AF_INET;
	        addr4.sin_port = addr6->sin6_port;
	        memcpy(&addr4.sin_addr.s_addr, addr6->sin6_addr.s6_addr+12, sizeof(addr4.sin_addr.s_addr));
	        memcpy(addr, &addr4, sizeof(addr4));
	        std::cout << "IPv4 Mapped in Ipv6 converted to IPv4" << std::endl;
	    }
	}
}

/**
    Converts Ip address in byte array to human readable format

    @param 	addr 		Address to convert.
    @param 	adrr_size 	Address size to convert.
    @returns Address in string format.
*/

std::string convertIpByteArrayToString(const unsigned char *addr, size_t adrr_size) 
{
	if (adrr_size == IPV4_ADDR_LENGTH) {
		char str[INET_ADDRSTRLEN];
		sprintf(str, "%d.%d.%d.%d",
	     addr[0], addr[1], addr[2], addr[3]);
		
		return str;
	}
	else if (adrr_size == IPV6_ADDR_LENGTH) {
		char str[INET6_ADDRSTRLEN];
		sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 (int)addr[0], (int)addr[1], (int)addr[2], (int)addr[3],
                 (int)addr[4], (int)addr[5], (int)addr[6], (int)addr[7],
                 (int)addr[8], (int)addr[9], (int)addr[10], (int)addr[11],
                 (int)addr[12], (int)addr[13], (int)addr[14], (int)addr[15]);

		return str;
	}
	else {
		return "";
	}
}


/**
    Converts Ip address in human readable format to struct sockaddr_storage

    @param 	addr 		Address in human readable format to convert.
    @param 	sin_family 	Address family.
    @returns Address in struct sockaddr_storage.
*/

sockaddr_storage convertIpToSockAddr(const char *addr, sa_family_t sin_family) 
{
	struct sockaddr_storage ss;
	if (sin_family == AF_INET) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&ss;
		bool result = inet_pton(AF_INET, addr, &addr4->sin_addr);
		if (!result)
			inet_pton(AF_INET, "0.0.0.0", &addr4->sin_addr);
		addr4->sin_family = AF_INET;
	}
	else if (sin_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&ss;
		bool result = inet_pton(AF_INET6, addr, &addr6->sin6_addr);
		if (!result)
			inet_pton(AF_INET6, "0:0:0:0:0:0:0:0", &addr6->sin6_addr);
		addr6->sin6_family = AF_INET6;
	}
	else {
		std::cout << "Wrong IP version" << std::endl;
	}

	convertIpv4MappedIpv6ToIpv4(&ss);
	return ss;
}

void test(const char *addr, sa_family_t sin_family) 
{
	struct sockaddr_storage ss = convertIpToSockAddr(addr, sin_family);

	unsigned char addr_buffer[IPV6_ADDR_LENGTH];
	memset(addr_buffer, 0, IPV6_ADDR_LENGTH);
	size_t addr_buffer_len = 0;

	convertSockAddrToByteArray((struct sockaddr*)&ss, addr_buffer, &addr_buffer_len);
	std::string addr_str = convertIpByteArrayToString(addr_buffer, addr_buffer_len);
	std::cout << "IP: " << addr_str << std::endl;
	std::string addr_str_ntop = convertSockAddrToStringNtop((struct sockaddr*)&ss);
	std::cout << "IP(n_top): " << addr_str_ntop << std::endl;
}

int main(int argc, char *argv[]) 
{
  test("192.0.2.33", AF_INET);
  test("10.192.168.55", AF_INET);
  test("2001:db8:8714:3a90::12", AF_INET6);
  test("0:0:0:0:0:FFFF:204.152.189.116", AF_INET6);
  return 0;
}