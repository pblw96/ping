// A simple ICMP ping utility implemented in C++ using raw sockets.
// Sends ICMP Echo Requests to a specified hostname and measures RTT.

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

constexpr size_t PACKET_SIZE = 64;
constexpr size_t RCV_BUFFER_SIZE = 1024;

unsigned short calculate_checksum(unsigned short *paddress, int len) {
  int nleft = len;
  int sum = 0;
  unsigned short *w = paddress;
  unsigned short answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *((unsigned char *)&answer) = *(unsigned char *)w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return answer;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "USAGE: sudo " << argv[0] << " <hostname>" << std::endl;
    return EXIT_FAILURE;
  }

  if (geteuid() != 0) {
    std::cerr << "This program must be run as root." << std::endl;
    return EXIT_FAILURE;
  }

  // Create raw socket
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    std::cerr << std::strerror(errno) << std::endl;
    return EXIT_FAILURE;
  }

  struct timeval tv;
  tv.tv_sec = 2;
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  // Resolve hostname
  struct addrinfo hints;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_RAW;

  const char *hostname = argv[1];
  struct addrinfo *res;
  int status = getaddrinfo(hostname, NULL, &hints, &res);

  if (status != 0) {
    std::cerr << "DNS error: " << gai_strerror(status) << std::endl;
    return EXIT_FAILURE;
  }

  struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
  char *ip_string = inet_ntoa(ipv4->sin_addr);

  std::cout << "PING " << hostname << " (" << ip_string << "): " << PACKET_SIZE
            << " data bytes" << std::endl;

  unsigned int seq;
  unsigned int succ_res = 0;
  unsigned int fail_res = 0;
  for (seq = 0; seq < 4; seq++) {
    char packet[PACKET_SIZE];
    std::memset(&packet, 0, sizeof(packet));
    struct icmphdr *icmp_hdr = (struct icmphdr *)packet;
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = getpid();
    icmp_hdr->un.echo.sequence = seq + 1;
    icmp_hdr->checksum =
        calculate_checksum((unsigned short *)packet, sizeof(packet));

    struct sockaddr_in *dest_addr = (struct sockaddr_in *)res->ai_addr;

    const auto start_time = std::chrono::steady_clock::now();
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)dest_addr,
               sizeof(struct sockaddr_in)) <= 0) {
      std::cerr << std::strerror(errno) << std::endl;
      fail_res++;
      continue;
    }

    char buffer[RCV_BUFFER_SIZE];
    struct sockaddr_in from_addr;
    socklen_t addr_len = sizeof(from_addr);

    if (recvfrom(sockfd, buffer, sizeof(buffer), 0,
                 (struct sockaddr *)&from_addr, &addr_len) < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        std::cerr << "Request timed out." << std::endl;
      } else {
        std::cerr << "Receive error: " << std::strerror(errno) << std::endl;
      }
      fail_res++;
    } else {
      const auto end_time = std::chrono::steady_clock::now();
      const auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
          end_time - start_time);

      struct iphdr *ip_reply = (struct iphdr *)buffer;
      struct icmphdr *icmp_reply =
          (struct icmphdr *)(buffer + ip_reply->ihl * 4);

      if (icmp_reply->type == ICMP_ECHOREPLY &&
          icmp_reply->un.echo.id == getpid()) {
        std::cout << "Reply from " << ip_string << " in " << rtt.count()
                  << " ms" << std::endl;
        succ_res++;
      }
    }

    sleep(1);
  }

  freeaddrinfo(res);
  close(sockfd);

  std::cout << "\nPackets sent/success/fail: " << seq << "/" << succ_res << "/"
            << fail_res << std::endl;

  return 0;
}
