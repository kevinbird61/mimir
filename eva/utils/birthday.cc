/**
 * Utils - calculate the probability of birthday problem 
 */
#include <cmath>
#include <string>
#include <iostream>
#include <unistd.h>

using namespace std;

int main(int argc, char **argv){
    int ch,flag=0; // default is p
    int param1=-1;
    float param2=-1.0;
    while((ch=getopt(argc, argv, "pdn1:2:")) != -1)
    {
        switch(ch)
        {
            case 'p':
                flag=0;
                break;
            case 'n':
                flag=1;
                break;
            case 'd':
                flag=2;
                break;
            case '1':
                param1=atoi(optarg);     
                break;
            case '2':
                param2=atof(optarg);
                break;
        }
    }

    if(param1==-1 || param2==-1.0){
        cerr << "Need to use -1 <param 1> -2 <param 2> to specify N, d or P, d" << endl;
    }

    if(flag==1){
        // N(P,d)
        cout << "(Collisiton Probability) P: " << param2 << endl;
        cout << "(Hashing space) d: " << param1 << endl;
        cout << "(Minimal number of execution that can cause collision) N( "<< param2 << " ): " << sqrtf(2*param1*logf(1.0/(1.0-param2))) + 0.5 << endl; 
    } else if(flag==0){
        // P(N,d): default
        cout << "(Number of execution that can cause collision) N: " << param2 << endl;
        cout << "(Hashing space) d: " << param1 << endl;
        cout << "(Collisiton Probability) P( "<< param2 << " ): " <<  (1.0-expf(-(param2*(param2-1))/(2.0*param1))) << endl; 
    } else if(flag==2){
        // d(n,P)
        cout << "(Collisiton Probability) P: " << param2 << endl;
        cout << "(Number of execution that can cause collision) N: " << param1 << endl;
        cout << "Correspond table size: " << (-(param1)*(param1-1))/(2*logf(1-param2)) << endl;
    }
}