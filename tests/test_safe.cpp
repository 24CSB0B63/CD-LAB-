#include <iostream>
#include <string>

// Mock sink function
void exec_query(const char* q) {
    std::cout << "Executing: " << q << std::endl;
}

int main() {
    // Looks complex, but all data is constant (Safe)
    std::string part1 = "SELECT * FROM ";
    std::string part2 = "inventory";
    
    std::string table = part2;
    std::string query = part1 + table + " WHERE count > 0";
    
    exec_query(query.c_str()); // Should NOT be detected

    return 0;
}
