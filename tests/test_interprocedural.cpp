#include <iostream>
#include <string>

using namespace std;

void exec_query(const char* q) {
    cout << "Executing: " << q << endl;
}

string build_query(const string& input) {
    string base = "SELECT * FROM users WHERE arg='";
    return base + input + "'";
}

void run_wrapper(const char* query) {
    exec_query(query); 
}

int main() {
    string user_input;
    cout << "Enter username: ";
    cin >> user_input; 
    string final_query = build_query(user_input);
    run_wrapper(final_query.c_str());
    return 0;
}
