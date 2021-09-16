#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <bitset>
#include <cmath>
#include <map>
#include <fstream>
#include <algorithm>

using namespace std;

//problem 1
string hex_to_base64(string s) {
    unsigned int hex_digit;
    string bin;
    string ret;
    string b64_index_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    //convert each char in the string to hex
    for (char c: s) { 
        stringstream ss;
        ss << hex << c;
        ss >> hex_digit;

        bitset<4> bs(hex_digit);
        bin += bs.to_string();
    }
    //convert hex to decimal and look up ascii value 
    for (int i=0; i < bin.length(); i+=6) {   
        string chunk = bin.substr(i, 6);
        if (chunk.length() == 2) {
            if (chunk.find("1")) {  
                ret += b64_index_table[stoi(chunk + "0000", 0, 2)];
            }
            ret += "==";
            return ret;

        }
        else if (chunk.length() == 4) {
            if (chunk.find("1")) { 
                //chunk += "00"; 
                ret += b64_index_table[stoi(chunk + "00", 0, 2)];
            }
            ret += "=";
            return ret;
        }
        
        int b64_index = stoi(bin.substr(i, 6), 0, 2);
        ret += b64_index_table[b64_index];
        
    }
    
    return ret;
}


//problem 2
string xorbuf(string a, string b) {
    if (a.length() != b.length()) { 
        cout << "invalid input!" << endl;
        exit(9);
    }
    unsigned int hex_digit_a;
    unsigned int hex_digit_b;
    unsigned int xord;
    

    string bin_a;
    string bin_b;
    string ret;

    for (int i = 0; i < a.length(); i++) {
        stringstream ssa;
        ssa << hex << a[i];
        ssa >> hex_digit_a;

        stringstream ssb;
        ssb << hex << b[i];
        ssb >> hex_digit_b;

        xord = hex_digit_a ^ hex_digit_b;
        
        stringstream ss;
        ss << hex << xord;
        ret += ss.str();
        
    }
    return ret;
}


//problem 3
map< float, pair<int, string> > single_byte_xor_decrypt(string s) {
    char xord;

    map<char, float> freq_map = {
    {'a', 8.24},    {'b', 1.51},    {'c', 2.81},    {'d', 4.29},
    {'e', 12.81},   {'f', 2.25},    {'g', 2.03},    {'h', 6.15},
    {'i', 6.15},    {'j', 0.15},    {'k', 0.78},    {'l', 4.06},
    {'m', 2.43},    {'n', 6.81},    {'o', 7.57},    {'p', 1.95},
    {'q', 0.10},    {'r', 6.04},    {'s', 6.38},    {'t', 9.14},
    {'u', 2.78},    {'v', 0.99},    {'w', 2.38},    {'x', 0.15},
    {'y', 1.99},    {'z', 0.07}, {' ', 13}
};


    string decoded;
    int len = s.length();

    for (int i=0; i< len; i+=2) {
            string byte = s.substr(i, 2);
            char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
            decoded.push_back(chr);
    }
    // cout << decoded << endl;


    map< float, pair<int, string> > ret;

    for(int i = 0 ; i < 255; i++) {
        float score = 0;
        string out;
        for (char c:decoded) {
            xord = c ^ i;

            out += xord;

            float f = freq_map.find(tolower(xord))->second;
            if (f) {
                score += f;
            }
        }
        //auto-sorted
    ret.insert(make_pair(score, make_pair(i, out)));
    }
    for(auto elem : ret)
{
//    std::cout << elem.first << " " << elem.second.first << " " << elem.second.second << "\n";
}
return ret;
}


map< float, pair<string, string> > find_xord() {
    map< float, pair<int, string> >::reverse_iterator last;
    map< float, pair<string, string> > ret;

    string line;
    ifstream file("4.txt");
    while (getline (file, line)) {
        stringstream ss;
        ss << line;
        cout << ss.str() << endl;
        last = single_byte_xor_decrypt(ss.str()).rbegin();
        // cout << last->first << " " << last->second.first << endl;
        ret.insert(make_pair(last->first, make_pair(ss.str(), last->second.second)));
    }

    cout << ret.size() << endl;
    for(auto elem : ret) {
        std::cout << elem.first << " " << elem.second.first << " " << elem.second.second << "\n";
    }
// Close the file
file.close();

return ret;
}

string repeating_key_xor(string s) {
    char hex_digit;
    string ret;
    string bin;

    // s.erase( remove( s.begin(), s.end(), ' ' ), s.end () );
    for (int i=0; i<s.length(); i+=3) {
        char x1 = s[i] ^ 'I';
        char x2 = s[i+1] ^ 'C';
        char x3 = s[i+2] ^ 'E'; 
        bin.push_back(x1);
        bin.push_back(x2);
        bin.push_back(x3);
    }
    for (char c: bin) { 
        stringstream ss;
        ss << hex << (int)c;

        ret += ss.str();
    }
    cout << ret << endl;

    // string nows;
    // stringstream ss(s);
    // ss >> skipws >> nows;
    // cout << nows << endl;
    return ret;
}

int main(int argc, char* argv[]) {
    // cout << hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") << endl;
    // cout << xorbuf("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") << endl;
    // char t = 'a' ^ 1;    
    // cout << t << endl;
    // single_byte_xor_decrypt("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b373");
    // find_xord(); 
    repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
    // repeating_key_xor("I go crazy when I hear a cymbal");
    return 0;
}
