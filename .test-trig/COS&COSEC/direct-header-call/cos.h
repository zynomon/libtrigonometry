#ifndef COS_H
#define COS_H

#include <string>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <ctime>
#include <functional>
#include <atomic>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define write _write
#define read _read
#define close _close
#define dup _dup
#define dup2 _dup2
#define open _open
#define pipe(fds) _pipe(fds, 1024, 0)

#define O_WRONLY _O_WRONLY
#define O_CREAT _O_CREAT
#define O_TRUNC _O_TRUNC
#define O_RDONLY _O_RDONLY
#else
#include <unistd.h>
#include <limits.h>
#include <execinfo.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#endif

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
#define STDERR_FILENO 2
#endif

inline const char* irs() {
    return "\n\n▒▒▒█   ▒▒▒█   ▒▒▒█   █▒▒█   █▒▒▒   █▒▒▒   █▒▒▒   █▒▒▒\n\n";
}

struct CrashInfo {
    std::string signalName;
    int signalNumber;
    std::string stackTrace;
    std::string timestamp;
    std::string logPath;
    std::string executableName;
    std::string startTime;
    long long sessionDurationMs;

    std::string getFormattedDuration() const {
        long long hours = sessionDurationMs / (1000 * 60 * 60);
        long long minutes = (sessionDurationMs / (1000 * 60)) % 60;
        long long seconds = (sessionDurationMs / 1000) % 60;
        long long centiseconds = (sessionDurationMs / 10) % 100;

        char buffer[12];
        snprintf(buffer, sizeof(buffer), "%02lld:%02lld:%02lld:%02lld",
                 hours, minutes, seconds, centiseconds);
        return std::string(buffer);
    }
};

class COS {
public:
    using CrashCallback = std::function<void(const CrashInfo&)>;

private:
    std::string logPath;
    bool logSaved;
    std::string executableName;
    std::string startTime;
    std::string stackTrace;
    CrashCallback crashCallback;
    time_t startTimeT;

    inline static std::atomic<COS*> globalInstance{nullptr};

    int savedStdout;
    int logFd;
    int pipeFds[2];
    std::atomic<bool> teeRunning;

    static const size_t BUFFER_SIZE = 1024;

    inline std::string getTimestampForFilename() const {
        time_t now = time(nullptr);
        struct tm tm = {};
#ifdef _WIN32
        localtime_s(&tm, &now);
#else
        localtime_r(&now, &tm);
#endif
        char buffer[32];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d_%H-%M-%S", &tm);
        return std::string(buffer);
    }

    inline std::string getTimestampForLog() const {
        time_t now = time(nullptr);
        struct tm tm = {};
#ifdef _WIN32
        localtime_s(&tm, &now);
#else
        localtime_r(&now, &tm);
#endif
        char buffer[32];
        strftime(buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", &tm);
        return std::string(buffer);
    }

    std::string getExecutableNameInternal() const {
#ifdef _WIN32
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        std::string fullPath(path);
        size_t pos = fullPath.find_last_of("\\/");
        std::string exeName = (pos == std::string::npos) ? fullPath : fullPath.substr(pos + 1);
        size_t extPos = exeName.find_last_of('.');
        if (extPos != std::string::npos) {
            exeName.resize(extPos);
        }
        return exeName;
#else
        char path[PATH_MAX];
        ssize_t count = readlink("/proc/self/exe", path, PATH_MAX);
        if (count != -1) {
            path[count] = '\0';
            std::string fullPath(path);
            size_t pos = fullPath.find_last_of('/');
            return (pos == std::string::npos) ? fullPath : fullPath.substr(pos + 1);
        }
        return "app";
#endif
    }

    inline std::string getTempDir() const {
        std::string appid = executableName;
        std::string timestamp = getTimestampForFilename();

#ifdef _WIN32
        const char* tempDir = std::getenv("TEMP");
        if (!tempDir) tempDir = std::getenv("TMP");
        if (!tempDir) tempDir = "C:\\Temp";
        return std::string(tempDir) + "\\" + appid + "_" + timestamp + ".log";
#else
        return "/tmp/" + appid + "_" + timestamp + ".log";
#endif
    }

#ifndef _WIN32
    std::string captureStackTrace() const {
        const int MAX_FRAMES = 32;

        void* buffer[MAX_FRAMES];
        int numFrames = backtrace(buffer, MAX_FRAMES);

        std::string result;
        result.reserve(numFrames * 128);

        char** symbols = backtrace_symbols(buffer, numFrames);
        if (symbols) {
            for (int i = 0; i < numFrames; i++) {
                result += symbols[i];
                result += "\n";
            }
            free(symbols);
        }
        return result;
    }
#endif

    void setupSignalHandlers() {
        std::signal(SIGTERM, signalHandler);
        std::signal(SIGINT, signalHandler);
        std::signal(SIGABRT, signalHandler);
        std::signal(SIGFPE, signalHandler);
        std::signal(SIGILL, signalHandler);
        std::signal(SIGSEGV, signalHandler);

#ifndef _WIN32
        std::signal(SIGBUS, signalHandler);
        std::signal(SIGQUIT, signalHandler);
        std::signal(SIGTRAP, signalHandler);
#endif
    }

    static void signalHandler(int sigNum) {
        COS* instance = globalInstance.load(std::memory_order_acquire);
        if (instance) {
            instance->handleSignal(sigNum);
        }
    }

    inline const char* getSignalName(int sigNum) const {
        switch(sigNum) {
        case SIGTERM: return "SIGTERM";
        case SIGINT: return "SIGINT";
        case SIGABRT: return "SIGABRT";
        case SIGFPE: return "SIGFPE";
        case SIGILL: return "SIGILL";
        case SIGSEGV: return "SIGSEGV";
#ifndef _WIN32
        case SIGBUS: return "SIGBUS";
        case SIGQUIT: return "SIGQUIT";
        case SIGTRAP: return "SIGTRAP";
#endif
        default: return "UNKNOWN_SIGNAL";
        }
    }

    static void* teeThreadFunc(void* arg) {
        COS* instance = static_cast<COS*>(arg);

        char buffer[BUFFER_SIZE];

        while (instance->teeRunning.load(std::memory_order_acquire)) {
            ssize_t bytes_read = read(instance->pipeFds[0], buffer, sizeof(buffer));

            if (bytes_read < 0 && errno == EINTR)
                continue;
            if (bytes_read <= 0)
                break;

            ssize_t written = 0;
            while (written < bytes_read) {
                ssize_t result = write(instance->savedStdout, buffer + written, bytes_read - written);
                if (result < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                written += result;
            }

            if (instance->logFd != -1) {
                ssize_t log_written = 0;
                while (log_written < bytes_read) {
                    ssize_t result = write(instance->logFd, buffer + log_written, bytes_read - log_written);
                    if (result < 0) {
                        if (errno == EINTR) continue;
                        break;
                    }
                    log_written += result;
                }
            }
        }
        return nullptr;
    }

    void handleSignal(int sigNum) {
        const char* signalName = getSignalName(sigNum);
        std::string currentTime = getTimestampForLog();

        const char* crashMsg = "\n!!! A CRASH SIGNAL FAILURE CAUGHT !!!\n";
        write(STDOUT_FILENO, crashMsg, strlen(crashMsg));

#ifndef _WIN32
        stackTrace = captureStackTrace();
        if (!stackTrace.empty()) {
            std::string traceMsg = "\n The Crash Signal  Trace; ";
            traceMsg += irs();
            traceMsg += stackTrace;
            traceMsg += irs();
            write(STDOUT_FILENO, traceMsg.c_str(), traceMsg.length());
        }
#endif

        saveLog(std::string("Crashed: ") + signalName);

        if (crashCallback) {
            time_t endTime = time(nullptr);
            long long durationMs = (long long)(difftime(endTime, startTimeT) * 1000);

            CrashInfo info;
            info.signalName = signalName;
            info.signalNumber = sigNum;
            info.stackTrace = stackTrace;
            info.timestamp = currentTime;
            info.logPath = logPath;
            info.executableName = executableName;
            info.startTime = startTime;
            info.sessionDurationMs = durationMs;

            crashCallback(info);
        }

        _exit(128 + sigNum);
    }

public:
    COS() : logSaved(false), crashCallback(nullptr),
        savedStdout(-1), logFd(-1), teeRunning(true) {
        pipeFds[0] = pipeFds[1] = -1;

        executableName = getExecutableNameInternal();
        logPath = getTempDir();

        startTimeT = time(nullptr);
        startTime = getTimestampForLog();

        savedStdout = dup(STDOUT_FILENO);

        logFd = open(logPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (logFd != -1) {
            const char* header1 = "- DATA -----------------------------------------------------------\n";
            write(logFd, header1, strlen(header1));

            std::string appLine = "App: " + executableName + "\n";
            write(logFd, appLine.c_str(), appLine.length());

            std::string timeLine = "Start: " + startTime + "\n";
            write(logFd, timeLine.c_str(), timeLine.length());

            const char* header2 = "------------------------------------------------- CAPTURED LOGS -\n";
            write(logFd, header2, strlen(header2));
        }

        if (pipe(pipeFds) == 0) {
            dup2(pipeFds[1], STDOUT_FILENO);
            dup2(pipeFds[1], STDERR_FILENO);
            close(pipeFds[1]);

            pipeFds[1] = -1;

            pthread_t thread;
            pthread_attr_t attr;
            pthread_attr_init(&attr);

#ifndef _WIN32
            pthread_attr_setstacksize(&attr, 64 * 1024);
#endif

            pthread_create(&thread, &attr, teeThreadFunc, this);
            pthread_detach(thread);
            pthread_attr_destroy(&attr);
        }

        globalInstance.store(this, std::memory_order_release);
        setupSignalHandlers();

        std::string initMsg = " Outputs of " + executableName + " in this Session \n Are saved in this following file path : " + logPath + "\n";
        write(STDOUT_FILENO, initMsg.c_str(), initMsg.length());
    }

    ~COS() {
        if (!logSaved) {
            saveLog("Normal exit");
        }

        teeRunning.store(false, std::memory_order_release);

        if (savedStdout != -1) {
            dup2(savedStdout, STDOUT_FILENO);
            dup2(savedStdout, STDERR_FILENO);
            close(savedStdout);
        }

        if (pipeFds[0] != -1) close(pipeFds[0]);
        if (logFd != -1) close(logFd);

        COS* expected = this;
        globalInstance.compare_exchange_strong(expected, nullptr,
                                               std::memory_order_acq_rel, std::memory_order_acquire);
    }

    inline void setCrashCallback(CrashCallback callback) {
        crashCallback = callback;
    }

    void saveLog(const std::string& exitReason) {
        if (logSaved) return;
        logSaved = true;

        time_t endTime = time(nullptr);
        long long durationMs = (long long)(difftime(endTime, startTimeT) * 1000);

        char durationBuffer[32];
        snprintf(durationBuffer, sizeof(durationBuffer), "%02lld:%02lld:%02lld:%02lld",
                 durationMs / (1000 * 60 * 60),
                 (durationMs / (1000 * 60)) % 60,
                 (durationMs / 1000) % 60,
                 (durationMs / 10) % 100);

        const char* footer1 = "\n---------------------------------------------- Q/E/T \n";
        write(STDOUT_FILENO, footer1, strlen(footer1));

        std::string exitLine = "Exit: " + exitReason + " at " + getTimestampForLog() + "\n";
        write(STDOUT_FILENO, exitLine.c_str(), exitLine.length());

        std::string durationLine = "Duration: " + std::string(durationBuffer) + " (HH:MM:SS:CS)\n";
        write(STDOUT_FILENO, durationLine.c_str(), durationLine.length());
    }

    inline const std::string& getExecutableName() const { return executableName; }
    inline const std::string& getLogPath() const { return logPath; }
    inline const std::string& getStartTime() const { return startTime; }
    inline const std::string& getStackTrace() const { return stackTrace; }

    static void Tri_reset() {
        COS* instance = globalInstance.load(std::memory_order_acquire);
        if (instance) {
            instance->saveLog("Application restart initiated");
        }

#ifdef _WIN32
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        if (CreateProcessA(
                exePath,
                NULL,
                NULL,
                NULL,
                FALSE,
                0,
                NULL,
                NULL,
                &si,
                &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
#else
        for (int fd = 3; fd < 64; fd++) {
            close(fd);
        }
        execl("/proc/self/exe", "/proc/self/exe", (char*)NULL);
#endif
        exit(0);
    }

    static void Tri_term() {
        std::signal(SIGTERM, SIG_DFL);
        std::signal(SIGINT, SIG_DFL);
        std::signal(SIGABRT, SIG_DFL);
        std::signal(SIGFPE, SIG_DFL);
        std::signal(SIGILL, SIG_DFL);
        std::signal(SIGSEGV, SIG_DFL);
#ifndef _WIN32
        std::signal(SIGBUS, SIG_DFL);
        std::signal(SIGQUIT, SIG_DFL);
        std::signal(SIGTRAP, SIG_DFL);
#endif

        COS* instance = globalInstance.exchange(nullptr, std::memory_order_acq_rel);
        delete instance;

        exit(0);
    }

    COS(const COS&) = delete;
    COS& operator=(const COS&) = delete;
};


#endif // COS_H
