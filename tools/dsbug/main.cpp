#include <bits/stdc++.h>
using namespace std;

static void print_usage(const char* prog) {
    cerr << "dsbug — simple restore-log analyzer\n";
    cerr << "Usage: " << prog << " [logfile]...\n";
}

int main(int argc, char** argv){
    if(argc==1){
        // read stdin
        ios::sync_with_stdio(false);
        string line;
        vector<string> buf;
        while(getline(cin,line)){
            buf.push_back(line);
            // keep last 1000 lines to show context
            if(buf.size()>1000) buf.erase(buf.begin());
        }
        vector<string> inputs = buf;
        bool found=false;
        for(size_t i=0;i<inputs.size();++i){
            string s = inputs[i];
            string l = s;
            for(char &c: l) c = tolower((unsigned char)c);
            if(l.find("typereq")!=string::npos || l.find("type req")!=string::npos || (l.find("np")!=string::npos && l.find("explan")!=string::npos)){
                found=true;
                cout << "--- Match at line "<< (i+1) << " ---\n";
                size_t start = (i>=5)? i-5: 0;
                size_t end = min(inputs.size(), i+6);
                for(size_t j=start;j<end;++j){
                    cout << (j+1) << (j==i?" > ":"   ") << inputs[j] << "\n";
                }
                cout << "\nSuggestion: Collect full restore log and device console. 'typereq' often indicates a type/requirement mismatch or missing payload during restore. Check IPSW payloads, signatures, and that blobs are correct.\n";
            }
        }
        if(!found) cout << "No 'typereq' / 'np explanation' patterns found in input.\n";
        return 0;
    }

    // process files
    bool any=false;
    for(int i=1;i<argc;i++){
        string path = argv[i];
        if(path=="-h" || path=="--help"){ print_usage(argv[0]); return 0; }
        ifstream f(path);
        if(!f){ cerr<<"failed to open "<<path<<"\n"; continue; }
        any=true;
        vector<string> lines;
        string line;
        while(getline(f,line)) lines.push_back(line);
        cout<<"== analyzing "<<path<<" ("<<lines.size()<<" lines) ==\n";
        for(size_t j=0;j<lines.size();++j){
            string l = lines[j];
            string tl = l;
            for(char &c: tl) c = tolower((unsigned char)c);
            if(tl.find("typereq")!=string::npos || tl.find("type req")!=string::npos || (tl.find("np")!=string::npos && tl.find("explan")!=string::npos)){
                cout << "--- Match at line "<< (j+1) << " ---\n";
                size_t start = (j>=5)? j-5: 0;
                size_t end = min(lines.size(), j+6);
                for(size_t k=start;k<end;++k){
                    cout << (k+1) << (k==j?" > ":"   ") << lines[k] << "\n";
                }
                cout << "\nSuggestion: Collect full restore log and device console. 'typereq' often indicates a type/requirement mismatch or missing payload during restore. Check IPSW payloads, signatures, and that blobs are correct.\n";
            }
        }
    }
    if(!any) print_usage(argv[0]);
    return 0;
}
