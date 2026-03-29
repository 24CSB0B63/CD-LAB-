#include <iostream>
#include <string>

using namespace std;

void exec_query(const char* q) {}

int main() {
    string user;
    cin >> user;

    string query = "SELECT * FROM users WHERE name='" + user + "'";
    exec_query(query.c_str());
}
