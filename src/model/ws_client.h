#pragma once

#include <cstdint>
#include <string>

namespace etrace_diag {

// Minimal dependency-free RFC 6455 WebSocket client (ws:// only, no TLS).
// Sufficient for JSON line protocol against the model services. Text messages
// only; handles a single frame and continuation fragments; replies to pings.
class WsClient {
 public:
  ~WsClient();

  // Connects and completes the HTTP upgrade handshake. url: ws://host[:port]/path
  bool Connect(const std::string& url, uint64_t timeout_ms);

  // Sends one text frame (client->server frames are masked).
  bool SendText(const std::string& msg);

  // Blocks up to timeout_ms for one complete text message. Returns false on
  // timeout, close, or transport error.
  bool RecvText(std::string& out, uint64_t timeout_ms);

  void Close();
  bool IsOpen() const { return fd_ >= 0; }

 private:
  bool ReadExact(void* buf, size_t n, uint64_t timeout_ms);
  bool ReadFrame(uint8_t& opcode, std::string& payload, uint64_t timeout_ms);

  int fd_ = -1;
  uint32_t mask_key_ = 0;
};

}  // namespace etrace_diag