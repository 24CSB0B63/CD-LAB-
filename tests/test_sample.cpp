#include <iostream>

using namespace std;

void exec(string s)  {
    cout<<"Executing "<<s<<endl;
}

int main() {

    string a;
    cin>>a;

    string b = "select * from "+a;
    exec(b);
}