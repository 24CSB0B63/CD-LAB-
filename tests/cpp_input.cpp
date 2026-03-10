#include <iostream>
#include <string>

void exec_query(const char* q) {}

int main() {
    std::string user;
    std::cin >> user;

    std::string query = "SELECT * FROM users WHERE name='" + user + "'";
    exec_query(query.c_str());
}
