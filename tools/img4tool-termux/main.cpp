#include <bits/stdc++.h>
using namespace std;

static void usage(const char* p){
    cerr<<"img4tool-termux — minimal helper for inspecting img4 files\n";
    cerr<<"Usage: "<<p<<" inspect <file>\n";
}

string hex(const string &s){
    static const char* hexd = "0123456789ABCDEF";
    string out;
    for(unsigned char c: s){
        out.push_back(hexd[c>>4]);
        out.push_back(hexd[c&0xF]);
        out.push_back(' ');
    }
    return out;
}

int main(int argc, char** argv){
    if(argc<3){ usage(argv[0]); return 1; }
    string cmd = argv[1];
    if(cmd=="inspect"){
        string path = argv[2];
        ifstream f(path, ios::binary);
        if(!f){ cerr<<"failed to open "<<path<<"\n"; return 2; }
        vector<char> buf((istreambuf_iterator<char>(f)), istreambuf_iterator<char>());
        cout<<"File: "<<path<<" size="<<buf.size()<<" bytes\n";
        string head(buf.begin(), buf.begin()+min<size_t>(buf.size(), 32));
        cout<<"First 32 bytes (hex): "<<hex(head)<<"\n";
        // simple search for typereq
        string s(buf.begin(), buf.end());
        string lower=s;
        for(char &c: lower) c = tolower((unsigned char)c);
        if(lower.find("typereq")!=string::npos) cout<<"Found 'typereq' inside blob.\n";
        else cout<<"No 'typereq' found in blob.\n";
        return 0;
    }
    usage(argv[0]);
    return 1;
}
