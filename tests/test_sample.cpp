#include <iostream>

using namespace std;

void exec_query(string s)  {
    cout<<"Executing "<<s<<endl;
}

int main() {

    string a;
    cin>>a;

    string b = "select * from "+a;
    exec_query(b);
}