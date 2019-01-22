/*
    Utils - sorting the output result
    (need to run read_pcap_w.out first)
*/
#include <map>
#include <cmath>
#include <string>
#include <cstring>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

typedef pair<int, int> PAIR;

ostream& operator<<(ostream& out, const PAIR& p) {
  return out << p.first << " " << p.second;
}

int main(int argc, char **argv){
    int ch,input_type=0,extract=0;
    string inputfile("");
    while((ch=getopt(argc, argv, "e:hpif:")) != -1)
    {
        switch(ch)
        {
            case 'e':
                /* extract level: only write the ones which larger than mean 
                    - 0: do nothing
                    - 1: record only > mean
                    - 2: record only > mean + sd (Standard Deviation)
                    - 3: record only > mean + 2*sd
                    - 4: record only > mean + 3*sd
                */
                extract=atoi(optarg);          
                break;
            case 'p':
                input_type+='p';    // avoid several flags, overwrite the origin flag
                break;
            case 'i':
                input_type+='i';    // avoid several flags, overwrite the origin flag
                break;
            case 'h':
                input_type+='h';    // overwrite the origin flag
                break;
            case 'f':
                inputfile = string(optarg);
                break;
        }
    }
    // check
    if(input_type==0 || input_type=='h' || input_type != 'p' && input_type != 'i'){
        cout << "Error format!" << endl;
        cout << " -e <level>: extract level: only write the ones which larger than mean.\n"
            << "\t- 0: do nothing (if you don't specify -e), record everything.\n" 
            << "\t- 1: record only > mean\n"
            << "\t- 2: record only > mean + sd (Standard Deviation)\n"
            << "\t- 3: record only > mean + 2*sd\n"
            << "\t- 4: record only > mean + 3*sd" << endl;
        cout << " -p : sort key with port number." << endl;
        cout << " -i : sort key with IP address (inet_pton)." << endl;
        cout << " -h : print helping msg." << endl;
        cout << " -f <input file> : specified input file." << endl;
        exit(1);
    }

    ifstream unsorted(inputfile);
    ofstream sorted;
    string line, delimiter=" ";
    map<int, int> unsorted_list;
    map<string, int> unsorted_ip;
    unsigned int X=0, Xpow=0, Cnt=0;
    double mean=0.0, var=0.0;
    double sd=0.0;
    // Open unsorted file
    if(!unsorted.is_open()){
        // print error 
        cout<< "Input file error: Can't open, please specified an available file." << endl;
        cout << " -e <level>: extract level: only write the ones which larger than mean.\n"
            << "\t- 0: do nothing (if you don't specify -e), record everything.\n" 
            << "\t- 1: record only > mean\n"
            << "\t- 2: record only > mean + sd (Standard Deviation)\n"
            << "\t- 3: record only > mean + 2*sd\n"
            << "\t- 4: record only > mean + 3*sd" << endl;
        cout << " -p : sort key with port number." << endl;
        cout << " -i : sort key with IP address (inet_pton)." << endl;
        cout << " -h : print helping msg." << endl;
        cout << " -f <input file> : specified input file." << endl;
        exit(1);
    } else {
        // read line by line
        if(input_type == 'p'){
            // port number, no need to convert key format
            while(getline(unsorted, line)){
                unsigned int key=atoi(line.substr(0,line.find(delimiter)).c_str()), val=atoi(line.substr(line.find(delimiter)+1).c_str());
                unsorted_list[key]=val;
                X += val;
                Xpow += val*val;
                Cnt++;
            }
        } else if (input_type == 'i') {
            // ip addr, need to convert IP into binary format
            struct sockaddr_in ipv4;
            while(getline(unsorted, line)){
                unsigned int val = atoi(line.substr(line.find(delimiter)+1).c_str());
                // inet_pton(AF_INET, line.substr(0,line.find(delimiter)).c_str(), ipv4_buf);
                //inet_pton(AF_INET, line.substr(0,line.find(delimiter)).c_str(), &(ipv4.sin_addr));
                // inet_ntoa(ipv4.sin_addr)
                // unsorted_list[ipv4.sin_addr.s_addr]=atoi(line.substr(line.find(delimiter)+1).c_str());
                unsorted_ip[line.substr(0,line.find(delimiter))]=val;
                X += val;
                Xpow += val*val;
                Cnt++;
            }
        }
        unsorted.close();
        // cal var 
        if(input_type=='p'){
            for (map<int, int>::iterator iter = unsorted_list.begin();
                iter != unsorted_list.end();
                ++iter) {
                var += (iter->second-(X/Cnt))*(iter->second-(X/Cnt));
            }
        } else if(input_type=='i') {
            for (map<string, int>::iterator iter = unsorted_ip.begin();
                iter != unsorted_ip.end();
                ++iter) {
                var += (iter->second-(X/Cnt))*(iter->second-(X/Cnt));
            }
        }
        
        // cal E[X] and E[X^2]
        mean = X/(double)Cnt; // mean = E[X]
        sd = sqrtf((var/(double)Cnt));
        cout << "E[X]: " << mean << endl;
        cout << "Var[X]: " << (var/(double)Cnt) << endl;
        cout << "SD[X]: " << sd << endl;
        // write back 
        std::size_t sep = inputfile.find_last_of("/\\");
        std::string path = inputfile.substr(0, sep);
        std::string file = inputfile.substr(sep+1);
        // rename sorted file by input file
        sorted.open(path+"/sorted_"+file);
        if(sorted.is_open()){
            if(input_type=='p')
                for (map<int, int>::iterator iter = unsorted_list.begin();
                    iter != unsorted_list.end();
                    ++iter) {
                        switch (extract){
                            case 0:
                                sorted << *iter << "\n";
                                break;
                            default:
                                // 1~4
                                if(iter->second >= mean+(extract-1)*sd)
                                    sorted << *iter << "\n";
                                break;
                        }
                }
            else if(input_type=='i')
                for (map<string, int>::iterator iter = unsorted_ip.begin();
                    iter != unsorted_ip.end();
                    ++iter) {
                        switch (extract){
                            case 0:
                                sorted << iter->first << " " << iter->second << "\n";
                                break;
                            default:
                                // 1~4
                                if(iter->second >= mean+(extract-1)*sd)
                                    sorted << iter->first << " " << iter->second << "\n";
                                break;
                        }
                }
        }
        sorted.close();
    }
    return 0;
}