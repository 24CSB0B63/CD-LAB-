#include <iostream>
#include <string>

using namespace std;

void exec_query(const char* q) {
    cout << "Executing: " << q << endl;
}

int main() {
    string input;
    cout << "Enter sensitive data: ";
    cin >> input; 

    string proxy = input; 

    string query = "SELECT * FROM logs WHERE entry='";
    query = query + proxy;
    
    const char* final_ptr = query.c_str();

    exec_query(final_ptr); 

    return 0;
}
