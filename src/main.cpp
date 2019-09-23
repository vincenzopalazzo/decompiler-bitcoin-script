#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>

#include <bitcoincrypto/cpp/Ripemd160.hpp>
#include <bitcoincrypto/cpp/TestHelper.hpp>
#include <bitcoincrypto/cpp/Sha256Hash.hpp>
#include <bitcoincrypto/cpp/Sha256.hpp>
#include <bitcoincrypto/cpp/Base58Check.hpp>
#include <bitcoinlib/base58.h>

#include "opcode.h"

using namespace std;

int main(int argc, char *argv[]) {

    string hex(argv[1]);

    BitcoinOPCode bitcoinOpCode;

    string opcode = hex.substr(0, 2);
    int32_t optValue = std::stoul(opcode, nullptr, 16);
    auto optMap = bitcoinOpCode.opCodeList.find(optValue);
    string optCode = optMap->second;

    if (optCode == "OP_HASH160") {
        cout << "Finded the P2SHA";

        string scriptHash = hex.substr(4, hex.length() - 6);
        Bytes bytes = hexBytes(scriptHash.c_str());
        bytes.insert(bytes.begin(), 1, 5);
        
        string address = EncodeBase58Check(bytes);

        cout << "P2SH addresss is " << address;

        string endOpCode = hex.substr(hex.length() - 2, 2);
        int32_t optValueEnd = std::stoul(endOpCode, nullptr, 16);
        auto optMapEnd = bitcoinOpCode.opCodeList.find(optValueEnd);
        string optCodeEnd = optMapEnd->second;
        if(optCodeEnd == "OP_EQUAL"){

          cout << "\n\t----------------------------------------| Results |-----------------------------------" << endl;
          cout << "\t                               ###  Script PUB KEY HASH  ###                            " << endl;
          cout << "\t" << optCode << " "  << scriptHash << " " << optCodeEnd << endl;
          cout << "\t                                                                                      " << endl;
          cout << "\t The public key: " << address << "                                   " << endl;
          cout << endl;
          cout << "\t https://blockstream.info/address/" << address << endl;
          cout << "\t______________________________________________________________________________________"<< endl;
        }else{
            cout << "ERROR Parsing" << endl;
            return EXIT_FAILURE;
        }
    } else if (optCode == "OP_DUP") {
        cout << "Finded the P2PKH" << endl;

        string opcodeHahs = hex.substr(2, 2);
        int32_t optValueHash = std::stoul(opcodeHahs, nullptr, 16);
        auto optMapHash = bitcoinOpCode.opCodeList.find(optValueHash);
        string optCodeHash = optMapHash->second;

        if(optCodeHash == "OP_HASH160"){
          string optCodeKey = hex.substr(6, hex.length() - 10); // meno i 6 tolti all'inzio, meno i 4 alla fine, attenzione anche al operatore OP_PUSHBYTES_20
          string penultimoOpt = hex.substr(hex.length() - 4, 2);
          int32_t optpenultimoOpt = std::stoul(penultimoOpt, nullptr, 16);
          auto optMappenultimoOpt = bitcoinOpCode.opCodeList.find(optpenultimoOpt);
          string optCodepenultimoOpt = optMappenultimoOpt->second;
          if(optCodepenultimoOpt == "OP_EQUALVERIFY"){
            cout << "\n\n" << endl;
            string endOpt = hex.substr(hex.length() - 2, 2);
            int32_t optendOpt = std::stoul(endOpt, nullptr, 16);
            auto optMappendOpt = bitcoinOpCode.opCodeList.find(optendOpt);
            string optCodeendOpt = optMappendOpt->second;
            if(optCodeendOpt == "OP_CHECKSIG"){

              Bytes bytes = hexBytes(optCodeKey.c_str());

              char address[36];

              Base58Check::pubkeyHashToBase58Check(bytes.data(), 0x00, address);
              string stringAddr(address);

              cout << "\n\n" << endl;

              cout << " \t----------------------------------------| Results |-----------------------------------" << endl;
              cout << "\t                               ###  Script PUB KEY HASH  ###                            " << endl;
              cout << "\t" << optCode << " "  << optCodeHash << " " << optCodeKey << " " << optCodepenultimoOpt << " " << optCodeendOpt   << endl;
              cout << "\t                                                                                      " << endl;
              cout << "\t The public key: " << stringAddr << "                                   " << endl;
              cout << endl;
              cout << "\t https://blockstream.info/address/" << stringAddr << endl;
              cout << "\t______________________________________________________________________________________"<< endl;
            }else{
              cout << "ERROR Parsing" << endl;
              return EXIT_FAILURE;
            }
          }else{
            cout << "ERROR Parsing" << endl;
            return EXIT_FAILURE;
          }
        }else{
          cout << "ERROR Parsing" << endl;
          return EXIT_FAILURE;
        }
        //https://blockstream.info/block/000000000000000000062ca4263bc8106361e9d02055484a9e69283d73a650c3

    } else {
        cout << "Transaction P2PK\n";
        cout << optValue << endl;
        string key = hex.substr(2, hex.length() - 4);
        opcode = hex.substr(hex.length() - 2, 2);
        optValue = std::stoul(opcode, nullptr, 16);
        optMap = bitcoinOpCode.opCodeList.find(optValue);
        opcode = optMap->second;
        Bytes bytes = hexBytes(key.c_str());

        //SHA256
        Sha256Hash shaHash = Sha256::getHash(bytes.data(), bytes.size());

        uint8_t result[Ripemd160::HASH_LEN];
        Ripemd160::getHash(shaHash.value, sizeof(shaHash), result);

        char address[36];
        Base58Check::pubkeyHashToBase58Check(result, 0x00, address);

        cout << "\n\n" << endl;
        cout << " \t-------------------------------------------------| Results |---------------------------------------------" << endl;
        cout << "\t                                           ###  Script PUB KEY  ###                            " << endl;
        cout << "\t" << key << " " << opcode << endl;
        cout << endl;
        cout << "\t The public key: " << address <<  endl;
        cout << endl;
        cout << "\t https://blockstream.info/address/" << address <<  endl;
        cout << "\t_________________________________________________________________________________________________________"<< endl;
    }


    return EXIT_SUCCESS;
}

