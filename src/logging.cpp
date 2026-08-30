#include "logging.h"

#include <ctime>
#include <cstring>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>

namespace etrace_diag {

namespace {

const char* LevelName(LogLevel l) {
  switch (l) {
    case LogLevel::kDebug: return "DEBUG";
    case LogLevel::kInfo: return "INFO";
    case LogLevel::kWarn: return "WARN";
    case LogLevel::kError: return "ERROR";
  }
  return "INFO";
}

}  // namespace

LogLevel ParseLogLevel(const std::string& s) {
  if (s == "debug") return LogLevel::kDebug;
  if (s == "warn" || s == "warning") return LogLevel::kWarn;
  if (s == "error") return LogLevel::kError;
  return LogLevel::kInfo;
}

Logger& Logger::Instance() {
  static Logger l;
  return l;
}

void Logger::Init(const std::string& log_file, LogLevel level) {
  std::lock_guard<std::mutex> g(mu_);
  level_ = level;
  if (fd_ >= 0) {
    close(fd_);
    fd_ = -1;
  }
  if (!log_file.empty()) {
    fd_ = open(log_file.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
  }
}

void Logger::SetLevel(LogLevel level) {
  std::lock_guard<std::mutex> g(mu_);
  level_ = level;
}

void Logger::SetSink(std::function<void(const std::string&)> sink) {
  std::lock_guard<std::mutex> g(mu_);
  sink_ = std::move(sink);
}

void Logger::Log(LogLevel lvl, const char* fmt, ...) {
  if (static_cast<int>(lvl) < static_cast<int>(level_)) return;

  char msg[2048];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

  char ts[40];
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  struct tm tmv;
  gmtime_r(&tv.tv_sec, &tmv);
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmv);
  char line[2200];
  int n = snprintf(line, sizeof(line), "[%s.%03ldZ] [%s] %s\n", ts, tv.tv_usec / 1000,
                   LevelName(lvl), msg);
  if (n < 0) return;

  std::lock_guard<std::mutex> g(mu_);
  (void)!write(2, line, static_cast<size_t>(n));
  if (fd_ >= 0) (void)!write(fd_, line, static_cast<size_t>(n));
  if (sink_ && n > 1) sink_(std::string(line, static_cast<size_t>(n) - 1));
}

void LogDebug(const char* fmt, ...) {
  char buf[2048];
  va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
  Logger::Instance().Log(LogLevel::kDebug, "%s", buf);
}
void LogInfo(const char* fmt, ...) {
  char buf[2048];
  va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
  Logger::Instance().Log(LogLevel::kInfo, "%s", buf);
}
void LogWarn(const char* fmt, ...) {
  char buf[2048];
  va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
  Logger::Instance().Log(LogLevel::kWarn, "%s", buf);
}
void LogError(const char* fmt, ...) {
  char buf[2048];
  va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
  Logger::Instance().Log(LogLevel::kError, "%s", buf);
}

}  // namespace etrace_diag