cmake_minimum_required(VERSION 2.6)
project(decompile-bitcoin-script)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
		src/main.cpp

		includes/bitcoincrypto/cpp/Ripemd160.cpp
		includes/bitcoincrypto/cpp/Sha256.cpp
		includes/bitcoincrypto/cpp/Sha256Hash.cpp
		includes/bitcoincrypto/cpp/Utils.cpp
		includes/bitcoincrypto/cpp/Base58Check.cpp
		includes/bitcoincrypto/cpp/Uint256.cpp
		includes/bitcoincrypto/cpp/CurvePoint.cpp
		includes/bitcoincrypto/cpp/FieldInt.cpp
		includes/bitcoincrypto/cpp/ExtendedPrivateKey.cpp
		includes/bitcoincrypto/cpp/Sha512.cpp
		#includes/bitcoincrypto/cpp/ExtendedPrivateKey.cpp
		#includes/bitcoincrypto/cpp/ExtendedPrivateKey.cpp


		#Bitcoin Lib
		#includes/bitcoinlib/script.cpp
		#includes/bitcoinlib/script_error.cpp
		#includes/bitcoinlib/key_io.cpp
		#includes/bitcoinlib/pubkey.cpp
		#includes/bitcoinlib/sign.cpp
		#includes/bitcoinlib/standard.cpp
	)


add_executable(Decompiler ${SOURCE_FILES})

target_include_directories(Decompiler PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/includes)

target_include_directories(Decompiler PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/includes/bitcoincrypto/cpp)
