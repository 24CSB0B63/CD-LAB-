#include <iostream>
#include <string>

void exec_query(const char* q) {
    std::cout << "Running Query: " << q << std::endl;
}

int main() {
    std::string userInput;
    std::cout << "Search for user: ";
    std::cin >> userInput; // SOURCE

    // The pass will detect "SELECT" in this constant and flag the concatenation
    std::string query = "SELECT * FROM users WHERE name='";
    query += userInput;
    query += "' AND status='active'";

    exec_query(query.c_str()); // SINK
    return 0;
}


