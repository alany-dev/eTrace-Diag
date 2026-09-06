#include "model/ws_client.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <random>
#include <vector>

namespace etrace_diag {

namespace {

bool SetBlocking(int fd, bool blocking) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  if (blocking)
    flags &= ~O_NONBLOCK;
  else
    flags |= O_NONBLOCK;
  return fcntl(fd, F_SETFL, flags) == 0;
}

bool WaitFd(int fd, short events, uint64_t timeout_ms) {
  struct pollfd pfd = {fd, events, 0};
  int rc = poll(&pfd, 1, timeout_ms == 0 ? -1 : (int)timeout_ms);
  return rc > 0 && (pfd.revents & (events | POLLHUP | POLLERR));
}

std::string Base64(const unsigned char* data, size_t len) {
  static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    unsigned n = (unsigned)data[i] << 16;
    if (i + 1 < len) n |= (unsigned)data[i + 1] << 8;
    if (i + 2 < len) n |= (unsigned)data[i + 2];
    out += tbl[(n >> 18) & 63];
    out += tbl[(n >> 12) & 63];
    out += (i + 1 < len) ? tbl[(n >> 6) & 63] : '=';
    out += (i + 2 < len) ? tbl[n & 63] : '=';
  }
  return out;
}

}  // namespace

WsClient::~WsClient() { Close(); }

void WsClient::Close() {
  if (fd_ >= 0) {
    close(fd_);
    fd_ = -1;
  }
}

bool WsClient::ReadExact(void* buf, size_t n, uint64_t timeout_ms) {
  char* p = static_cast<char*>(buf);
  size_t got = 0;
  while (got < n) {
    if (!WaitFd(fd_, POLLIN, timeout_ms)) return false;
    ssize_t r = recv(fd_, p + got, n - got, 0);
    if (r <= 0) return false;
    got += (size_t)r;
  }
  return true;
}

bool WsClient::Connect(const std::string& url, uint64_t timeout_ms) {
  if (url.rfind("ws://", 0) != 0) return false;
  std::string rest = url.substr(5);
  std::string host, port = "80", path = "/";
  size_t slash = rest.find('/');
  if (slash != std::string::npos) {
    path = rest.substr(slash);
    rest = rest.substr(0, slash);
  }
  size_t colon = rest.rfind(':');
  if (colon != std::string::npos) {
    port = rest.substr(colon + 1);
    host = rest.substr(0, colon);
  } else {
    host = rest;
  }

  struct addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* res = nullptr;
  if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return false;

  int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sock < 0) {
    freeaddrinfo(res);
    return false;
  }
  SetBlocking(sock, false);
  int rc = ::connect(sock, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);
  if (rc != 0 && errno != EINPROGRESS) {
    close(sock);
    return false;
  }
  {
    struct pollfd pfd = {sock, POLLOUT, 0};
    int prc = poll(&pfd, 1, timeout_ms == 0 ? -1 : (int)timeout_ms);
    if (prc <= 0) {
      close(sock);
      return false;
    }
    int so_err = 0;
    socklen_t el = sizeof(so_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);
    if (so_err != 0) {
      close(sock);
      return false;
    }
  }
  SetBlocking(sock, true);
  fd_ = sock;

  unsigned char keybytes[16];
  std::mt19937_64 rng(std::random_device{}());
  for (int i = 0; i < 16; ++i) keybytes[i] = (unsigned char)(rng() & 0xFF);

  std::string req;
  req += "GET " + path + " HTTP/1.1\r\n";
  req += "Host: " + host + ":" + port + "\r\n";
  req += "Upgrade: websocket\r\n";
  req += "Connection: Upgrade\r\n";
  req += "Sec-WebSocket-Key: " + Base64(keybytes, 16) + "\r\n";
  req += "Sec-WebSocket-Version: 13\r\n";
  req += "\r\n";
  if (send(fd_, req.data(), req.size(), 0) != (ssize_t)req.size()) {
    Close();
    return false;
  }

  std::string resp;
  char c;
  size_t hdr_end = std::string::npos;
  while (resp.size() < 16384) {
    if (!ReadExact(&c, 1, timeout_ms)) {
      Close();
      return false;
    }
    resp += c;
    hdr_end = resp.find("\r\n\r\n");
    if (hdr_end != std::string::npos) break;
  }
  if (hdr_end == std::string::npos || resp.rfind("HTTP/1.1 101", 0) != 0) {
    Close();
    return false;
  }

  mask_key_ = (uint32_t)rng();
  return true;
}

bool WsClient::SendText(const std::string& msg) {
  if (fd_ < 0) return false;
  std::vector<unsigned char> frame;
  frame.reserve(14 + msg.size());
  frame.push_back(0x81);  // FIN + text
  size_t n = msg.size();
  if (n < 126) {
    frame.push_back(0x80 | (unsigned char)n);
  } else if (n < 65536) {
    frame.push_back(0x80 | 126);
    frame.push_back((unsigned char)(n >> 8));
    frame.push_back((unsigned char)(n & 0xFF));
  } else {
    frame.push_back(0x80 | 127);
    for (int i = 7; i >= 0; --i) frame.push_back((unsigned char)((n >> (i * 8)) & 0xFF));
  }
  frame.push_back((unsigned char)(mask_key_ >> 24));
  frame.push_back((unsigned char)(mask_key_ >> 16));
  frame.push_back((unsigned char)(mask_key_ >> 8));
  frame.push_back((unsigned char)(mask_key_ & 0xFF));
  for (size_t i = 0; i < n; ++i)
    frame.push_back((unsigned char)(msg[i] ^ ((mask_key_ >> ((3 - (i % 4)) * 8)) & 0xFF)));

  size_t sent = 0;
  while (sent < frame.size()) {
    ssize_t r = send(fd_, frame.data() + sent, frame.size() - sent, 0);
    if (r <= 0) return false;
    sent += (size_t)r;
  }
  return true;
}

bool WsClient::ReadFrame(uint8_t& opcode, std::string& payload, uint64_t timeout_ms) {
  unsigned char hdr[2];
  if (!ReadExact(hdr, 2, timeout_ms)) return false;

  bool fin = (hdr[0] & 0x80) != 0;
  bool masked = (hdr[1] & 0x80) != 0;
  opcode = hdr[0] & 0x0F;
  uint64_t len = hdr[1] & 0x7F;

  if (len == 126) {
    unsigned char ext[2];
    if (!ReadExact(ext, 2, timeout_ms)) return false;
    len = ((uint64_t)ext[0] << 8) | ext[1];
  } else if (len == 127) {
    unsigned char ext[8];
    if (!ReadExact(ext, 8, timeout_ms)) return false;
    len = 0;
    for (int i = 0; i < 8; ++i) len = (len << 8) | ext[i];
  }
  if (len > 64 * 1024 * 1024) return false;  // sanity cap

  unsigned char mkey[4] = {0};
  if (masked) {
    if (!ReadExact(mkey, 4, timeout_ms)) return false;
  }

  payload.resize(len);
  if (len && !ReadExact(&payload[0], len, timeout_ms)) return false;
  if (masked) {
    for (uint64_t i = 0; i < len; ++i) payload[i] ^= mkey[i % 4];
  }
  (void)fin;
  return true;
}

bool WsClient::RecvText(std::string& out, uint64_t timeout_ms) {
  out.clear();
  std::string payload;
  for (;;) {
    uint8_t opcode = 0;
    if (!ReadFrame(opcode, payload, timeout_ms)) return false;
    switch (opcode) {
      case 0x1:  // text
        out = payload;
        return true;
      case 0x0:  // continuation (tolerated; model messages are single-frame)
        return true;
      case 0x8:  // close
        Close();
        return false;
      case 0x9: {  // ping -> pong (client frames MUST be masked, RFC 6455 §5.1)
        unsigned char hdr[2] = {0x8A, (unsigned char)(0x80u | payload.size())};
        unsigned char mk[4] = {
            (unsigned char)(mask_key_ >> 24), (unsigned char)(mask_key_ >> 16),
            (unsigned char)(mask_key_ >> 8), (unsigned char)(mask_key_ & 0xFF)};
        std::vector<unsigned char> pong(hdr, hdr + 2);
        pong.insert(pong.end(), mk, mk + 4);
        for (size_t i = 0; i < payload.size(); ++i)
          pong.push_back((unsigned char)(payload[i] ^ mk[i % 4]));
        size_t sent = 0;
        while (sent < pong.size()) {
          ssize_t r = send(fd_, pong.data() + sent, pong.size() - sent, 0);
          if (r <= 0) return false;
          sent += (size_t)r;
        }
        break;
      }
      case 0xA:  // pong
        break;
      default:
        return false;
    }
  }
}

}  // namespace etrace_diag