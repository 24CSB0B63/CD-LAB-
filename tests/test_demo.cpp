#include <iostream>
#include <string>

using namespace std;

void exec_query(const char* q) {
    cout << "Running Query: " << q << endl;
}

int main() {
    string userInput;
    cout << "Search for user: ";
    cin >> userInput; 

    string query = "SELECT * FROM users WHERE name='";
    query += userInput;
    query += "' AND status='active'";

    exec_query(query.c_str()); 
    return 0;
}
