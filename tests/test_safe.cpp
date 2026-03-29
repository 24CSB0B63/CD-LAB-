#include <iostream>
#include <string>

using namespace std;

void exec_query(const char* q) {
    cout << "Executing: " << q << endl;
}

int main() {
    string part1 = "SELECT * FROM ";
    string part2 = "inventory";
    
    string table = part2;
    string query = part1 + table + " WHERE count > 0";

    string test;
    cin>>test;
    
    exec_query(query.c_str()); 

    return 0;
}
