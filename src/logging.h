#pragma once

#include <cstdarg>
#include <mutex>
#include <string>

namespace etrace_diag {

enum class LogLevel { kDebug = 0, kInfo = 1, kWarn = 2, kError = 3 };

LogLevel ParseLogLevel(const std::string& s);

class Logger {
 public:
  static Logger& Instance();

  // Opens `log_file` (appends). When `log_file` is empty, only stderr is used.
  void Init(const std::string& log_file, LogLevel level);
  void SetLevel(LogLevel level);
  LogLevel Level() const { return level_; }

  void Log(LogLevel lvl, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

 private:
  Logger() = default;
  std::mutex mu_;
  int fd_ = -1;           // log file fd (-1 = closed)
  LogLevel level_ = LogLevel::kInfo;
};

void LogDebug(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void LogInfo(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void LogWarn(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void LogError(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

}  // namespace etrace_diag