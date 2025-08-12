#ifndef SELF_PROTECTION_H
#define SELF_PROTECTION_H

#include <iostream>
#include <fstream>
#include <thread>
#include <random>
#include <unordered_map>
#include <dlfcn.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/sendfile.h>  
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <signal.h>
#include <queue>
#include <functional>
#include <elf.h>
#include <string.h>     
#include <linux/limits.h>

namespace self_protection {

// ================== 编译器指令 ==================
#define PROTECT_FUNCTION __attribute__((section(".protected"))) __attribute__((noinline))
#define SECURITY_ALWAYS_INLINE __attribute__((always_inline))

// ================== 基础工具模块 ==================
class ScopedFD {
    int fd_;
public:
    explicit ScopedFD(int fd = -1) : fd_(fd) {}
    ~ScopedFD() { if (fd_ != -1) close(fd_); }
    int get() const { return fd_; }
};

class SecureRandom {
    std::random_device rd;
    std::mt19937 gen;
public:
    SecureRandom() : gen(rd()) {}
    int range(int min, int max) {
        std::uniform_int_distribution<> dist(min, max);
        return dist(gen);
    }
};

void log_error(const std::string& msg, bool critical = false) {
    std::cerr << "[SECURITY] " << msg << " (" << strerror(errno) << ")\n";
    if (critical) exit(EXIT_FAILURE);
}

// ================== 核心保护模块 ==================
class CoreProtection {
public:
    static void prevent_core_dump() {
        rlimit limit{0, 0};
        setrlimit(RLIMIT_CORE, &limit);
    }

    static std::string get_self_path() {
        char buf[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
        return (len != -1) ? std::string(buf, len) : "";
    }

    static void overwrite_self() {
        std::string path = get_self_path();
        if (path.empty()) log_error("Get self path failed", true);

        ScopedFD src(open(path.c_str(), O_RDONLY));
        if (src.get() == -1) log_error("Open self failed", true);

        struct stat st;
        if (fstat(src.get(), &st) == -1) log_error("Fstat failed", true);

        std::string tmp = path + ".tmp";
        ScopedFD dst(open(tmp.c_str(), O_WRONLY|O_CREAT|O_EXCL, 0600));
        if (dst.get() == -1) log_error("Create temp failed", true);

        off_t offset = 0;
        if (sendfile(dst.get(), src.get(), &offset, st.st_size) == -1)
            log_error("File copy failed", true);

        std::string msg = "Terminated:" + std::to_string(SecureRandom().range(1,10000)) + "\n";
        write(dst.get(), msg.data(), msg.size());
        fsync(dst.get());

        if (rename(tmp.c_str(), path.c_str()) == -1)
            log_error("Final rename failed", true);
    }
};

// ================== 安全自毁函数声明 ==================
void security_self_destruct(const std::string& reason);

// ================== 反调试模块 ==================
class AntiDebug {
public:
    PROTECT_FUNCTION static void ptrace_check() {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
            security_self_destruct("Ptrace detected");
    }

    PROTECT_FUNCTION static void tracerpid_check() {
        std::ifstream status("/proc/self/status");
        std::string line;
        while (getline(status, line)) {
            if (line.find("TracerPid:") == 0) {  //兼容写法
                int pid = std::stoi(line.substr(11));
                if (pid != 0) check_debugger_process(pid);
                break;
            }
        }
    }

private:
    static void check_debugger_process(int pid) {
        std::string comm = "/proc/" + std::to_string(pid) + "/comm";
        std::ifstream f(comm);
        std::string name;
        if (f && getline(f, name) && (name.find("gdb") != std::string::npos || name.find("lldb") != std::string::npos)) {
            security_self_destruct("Debugger: " + name);
        }
    }
};

// ================== 内存保护模块 ==================
class MemoryGuard {
public:
    static void protect_all() {
        
        for (const auto& addr : function_addresses) {
            set_protection(addr);
            check_hooks(addr);
        }
    }

private:
    static void set_protection(void* func) {
        const size_t page_size = sysconf(_SC_PAGESIZE);
        uintptr_t start = reinterpret_cast<uintptr_t>(func) & ~(page_size - 1);
        size_t length = page_size; 
        if (mprotect(reinterpret_cast<void*>(start), length, PROT_READ) == -1)
            log_error("Memory protection failed", true);
    }

    static void check_hooks(void* func) {
        const uint8_t* code = static_cast<const uint8_t*>(func);
        const uint8_t danger_ops[] = {0xE9, 0xCC, 0x0F, 0x84};  // JMP, INT3, JZ 等指令
        for (size_t i = 0; i < 1; ++i) { 
            for (auto op : danger_ops) {
                if (code[i] == op) security_self_destruct("Hook detected");
            }
        }
    }

    static const std::vector<void*> function_addresses;
};

// ================== 动态检测调度器 ==================
class SecurityScheduler {
    SecureRandom rng;
    std::atomic<bool> running{true};

public:
    void start() {
        std::thread([this] {
            while (running) {
                int delay = rng.range(3000, 6000); // 3-6秒随机间隔
                std::this_thread::sleep_for(std::chrono::milliseconds(delay));
                execute_random_check();
            }
        }).detach();
    }

    void stop() { running = false; }

private:
    void execute_random_check() {
        switch (rng.range(0, 5)) {
            case 0: check_frida(); break;
            case 1: check_ld_preload(); break;
            case 2: check_vpn(); break;
            case 3: check_memory_integrity(); break;
            case 4: check_process_injection(); break;
        }
    }

    static void check_frida() {
        check_frida_port(27042);
        check_frida_threads();
    }

    static void check_frida_port(int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0)
            security_self_destruct("Frida port detected");
        close(sock);
    }

    static void check_frida_threads() {
        DIR* task_dir = opendir("/proc/self/task");
        if (!task_dir) return;

        dirent* ent;
        while ((ent = readdir(task_dir))) {
            std::string comm_path = std::string("/proc/self/task/") + ent->d_name + "/comm";
            std::ifstream comm(comm_path);
            std::string name;
            if (comm && getline(comm, name) && (name.find("gum-js") != std::string::npos || name.find("frida") != std::string::npos)) {
                security_self_destruct("Frida thread detected");
            }
        }
        closedir(task_dir);
    }

    static void check_ld_preload() {
        if (getenv("LD_PRELOAD"))
            security_self_destruct("LD_PRELOAD detected");
    }

    static void check_vpn() {
        ifaddrs* ifa;
        getifaddrs(&ifa);
        for (auto ptr = ifa; ptr; ptr = ptr->ifa_next) {
            std::string name(ptr->ifa_name);
            if (name.find("tun") != std::string::npos || name.find("ppp") != std::string::npos) {
                security_self_destruct("VPN detected");
            }
        }
        freeifaddrs(ifa);
    }

    static void check_memory_integrity() {
        MemoryGuard::protect_all();
    }

    static void check_process_injection() {
        std::ifstream maps("/proc/self/maps");
        std::string line;
        while (getline(maps, line)) {
            if (line.find("libfrida") != std::string::npos) {
                security_self_destruct("Frida library injected");
            }
        }
    }
};

// ================== 主保护管理器 ==================
class ProtectionManager {
    SecurityScheduler scheduler;

public:
    ProtectionManager() {
        CoreProtection::prevent_core_dump();
        MemoryGuard::protect_all();
        scheduler.start();
        setup_signal_handlers();
    }

private:
    static void setup_signal_handlers() {
        struct sigaction sa{};
        sa.sa_handler = [](int) { security_self_destruct("Signal triggered"); };
        sigaction(SIGTRAP, &sa, nullptr);
        sigaction(SIGSEGV, &sa, nullptr);
        sigaction(SIGILL, &sa, nullptr);
    }
};

// ================== 安全自毁函数定义 ==================
void security_self_destruct(const std::string& reason) {
    log_error(reason, false);
    CoreProtection::overwrite_self();
    exit(EXIT_FAILURE);
}

// ================== 内存保护元数据初始化 ==================
const std::vector<void*> MemoryGuard::function_addresses = {
    reinterpret_cast<void*>(AntiDebug::ptrace_check),
    reinterpret_cast<void*>(AntiDebug::tracerpid_check)
};

// 全局保护实例
ProtectionManager protection;

} // namespace self_protection

#endif // SELF_PROTECTION_H
//by.你好
//修复了大多数问题,修复了无法在后台保持的问题,考虑复用宽容，暂时将自我摧毁更换为自我降权，增加了断点内存判断增加了常见frida检查,增加随机刻度器，防止被预测拦截,优化了结构
