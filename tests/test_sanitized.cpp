#include <iostream>
#include <string>

using namespace std;

void mysql_query(const char* query) {
    cout << "Executing: " << query << endl;
}

string sanitize_input(const string& input) {
    string sanitized = "";
    for (char c : input) {
        if (c != '\'' && c != '"' && c != ';' && c != '\\') {
            sanitized += c;
        }
    }
    return sanitized;
}

int main() {
    string user_input;
    
    cin >> user_input;
    
    string clean_input = sanitize_input(user_input);
    
    string query = "SELECT * FROM users WHERE username = '" + clean_input + "'";
    
    mysql_query(query.c_str());

    return 0;
}
