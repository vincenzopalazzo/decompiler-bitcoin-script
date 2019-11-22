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

#include "opcode.hpp"

using namespace std;

std::string ToString(uint8_t bytes[Ripemd160::HASH_LEN]);
bool isWitness(std::string hexScript);
bool isP2WSH(std::string hexScript);
bool isP2WPKH(std::string hexScript);

int main(int argc, char *argv[]) {

    string hex(argv[1]);

    BitcoinOPCode bitcoinOpCode;

    string opcode = hex.substr(0, 2);
    int32_t optValue = std::stoul(opcode, nullptr, 16);
    auto optMap = bitcoinOpCode.opCodeList.find(optValue);
    string optCode = optMap->second;
    std::cout << "OP_CODE = " << optCode << std::endl;
    if (optCode == "OP_HASH160") {
        cout << "Finded the P2SH";

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
          cout << "\t                               ###  Script PAY TO SCRIPT HASH  ###                            " << endl;
          cout << "\t" << optCode << " "  << scriptHash << " " << optCodeEnd << endl;
          cout << "\t                                                                                      " << endl;
          cout << "\t The P2SH address: " << address << "                                   " << endl;
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
          //string optCodeKey = "03385adff37fd3d0a620ebc4e9866e81dda8ba8616e5ebcae899c7f51899267ae7";
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
/*
              Sha256Hash hashP2sh = Sha256::getHash(bytes.data(), bytes.size());

              uint8_t resultHas160[Ripemd160::HASH_LEN];
              Ripemd160::getHash(hashP2sh.value, sizeof(hashP2sh.value), resultHas160);
              vector<uint8_t> vectorHash160(resultHas160);*/
              //This operations is wrong
              bytes.insert(bytes.begin(), 1, 5);
              string p2pshAddress = EncodeBase58Check(bytes);
              
              cout << "\n\t----------------------------------------| Results |-----------------------------------" << endl;
              cout << "\t                               ###  Script PAY TO PUBLIC KEY HASH  ###                            " << endl;
              cout << "\t  Raw Script PubKey: " << hex << endl << endl;
              cout << "\t" << optCode << " "  << optCodeHash << " " << optCodeKey << " " << optCodepenultimoOpt << " " << optCodeendOpt   << endl;
              cout << "\t                                                                                      " << endl;
              cout << "\t The address: " << stringAddr << endl;
              cout << "\t The Hash160 pubkey: " << optCodeKey << endl;
              cout << "\t The P2PSH address: " << p2pshAddress << endl;
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

    } else if((optValue != std::stoul("0x00", nullptr, 16)) && (optValue != std::stoul("0x76", nullptr, 16))){
        cout << "Transaction P2PK\n";
        cout << optValue << endl;
        //string key = hex.substr(2, hex.length() - 4);
        string key = "033da9f8938a5b947a723df21b73fbd3985b719249324d2c705acfb97d63a5df9e";
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

        string typePubKey = "uncompressed";
        string flag = key.substr(0, 2);
        if(flag == "02"){
          typePubKey = "Compressed with y event";
        }else if(flag == "03"){
          typePubKey = "Compressed with y odd";
        }else{
          assert(flag == "04");
        }

        cout << "\n\n" << endl;
        cout << " \t-------------------------------------------------| Results |---------------------------------------------" << endl;
        cout << "\t                                           ###  Script PAY TO PUBLIC KEY  ###                            " << endl;
        cout << "\t" << key << " " << opcode << endl;
        cout << endl;
        cout << "\t The address: " << address << endl;
        cout << "\t The pubk key: " << key << " " << typePubKey << endl;
        cout << endl;
        cout << "\t https://blockstream.info/address/" << address <<  endl;
        cout << "\t_________________________________________________________________________________________________________"<< endl;
    }else if(isP2WPKH(hex)){
      std::cout << "P2WPKH script" << std::endl;
      
    }else if(isP2WSH(hex)){
      std::cout << "P2WSH script" << std::endl;
    }else{
      cout << "\n\n\n" << hex.substr(1, 2) << endl;
      cout << "\n\n ********** NO standard script **********\n\n" << endl;
    }
    return EXIT_SUCCESS;
}

bool isWitness(std::string hexScript){
  return (isP2WPKH(hexScript) || isP2WSH(hexScript));
}

bool isP2WSH(std::string hexScript){
  //Not work look the scrip python
  return ((hexScript.length() == 30 * 2) &&
          (std::stoul(hexScript.substr(0, 2), nullptr, 16) == std::stoul("0x00", nullptr, 16)));
}

//an example 00149d57c57c3573b58db6b50c10651fc23e40eac0a1
bool isP2WPKH(std::string hexScript){
  cout << "******** DEBUG P2WPKH ********" << std::endl;
  cout << "******** " << hexScript.length() << std::endl;
  cout << "******** " << hexScript.substr(0, 2) << std::endl;
  return ((hexScript.length() == 22 * 2) &&
          (std::stoul(hexScript.substr(0, 2), nullptr, 16) == std::stoul("0x00", nullptr, 16)));
}

std::string ToString(uint8_t bytes[Ripemd160::HASH_LEN]){
  std::string hashResult;
  std::stringstream stream;
  for(int i = 0; i < Ripemd160::HASH_LEN; i++){
      int valueInt = static_cast<int>(bytes[i]);
      stream << std::hex << std::setprecision(2) << std::setw(2) << std::setfill('0') << valueInt;
  }
  hashResult = stream.str();
  return hashResult;
}

