#include "正式版v1.0.hpp"

int main() {
    // 启动保护机制
    self_protection::ProtectionManager protection;

  
    std::this_thread::sleep_for(std::chrono::minutes(10)); // 模拟运行时间

    return 0;
}
