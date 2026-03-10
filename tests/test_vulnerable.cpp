#include <iostream>
#include <string>

// Mock sink function
void exec_query(const char* q) {
    std::cout << "Executing: " << q << std::endl;
}

int main() {
    std::string input;
    std::cout << "Enter sensitive data: ";
    std::cin >> input; // SOURCE

    // 1. Propagation through assignment
    std::string proxy = input; 

    // 2. Propagation through multiple concatenation steps
    std::string query = "SELECT * FROM logs WHERE entry='";
    query = query + proxy;
    query = query + "' AND type='ERROR'";

    // 3. Indirect access via pointer
    const char* final_ptr = query.c_str();

    exec_query(final_ptr); // SINK - Should trigger detection

    return 0;
}


