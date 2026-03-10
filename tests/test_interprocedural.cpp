#include <iostream>
#include <string>

void exec_query(const char* q) {
    std::cout << "Executing: " << q << std::endl;
}

std::string build_query(const std::string& input) {
    std::string base = "SELECT * FROM users WHERE arg='";
    return base + input + "'";
}

void run_wrapper(const char* query) {
    exec_query(query); // SINK
}

int main() {
    std::string user_input;
    std::cout << "Enter username: ";
    std::cin >> user_input; // SOURCE
    std::string final_query = build_query(user_input);
    run_wrapper(final_query.c_str());
    return 0;
}

