#include <iostream>
#include <vector>
#include <fstream>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#define sizebuf 128
using namespace std;


int main(int argc, char *argv[])
{

//=================================intializing libraries==============================================
	
	ERR_load_crypto_strings();
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

//=====================================================================================================

//===================================starting connection===============================================

cout<<"server step 1"<<endl;

	char* portnum = argv[2];
	int err;

	//new context pointer for new connection
  SSL_CTX * ctx = SSL_CTX_new(SSLv23_client_method());
  SSL * ssl;

	//set flags so it doesnt complain
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE,NULL);
	
	//gets new bio pointer
	BIO *con = BIO_new_ssl(ctx, 0);
	BIO_get_ssl(con, &ssl);

	//listen, connect and handshake
	BIO *accept = BIO_new_accept(portnum);	

if(BIO_do_connect(accept) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
				exit(1);	
 }

 if(BIO_do_handshake(accept) <= 0) {
        fprintf(stderr, "Error establishing SSL connection\n");
        ERR_print_errors_fp(stderr);
	      exit(1);
 }

//=======================================================================================================

//=================================read in public and private keys=======================================
	BIO *mem = NULL;
  RSA *rsaprivate = NULL;
	RSA *rsapublic = NULL;

	mem = BIO_new_file("rsaprivatekey.pem", "r");
  rsaprivate = PEM_read_bio_RSAPrivateKey( mem , NULL , NULL , NULL );
  BIO_free(mem);
	
	mem = NULL;
	mem = BIO_new_file("rsapublickey.pem", "r");
	rsapublic = PEM_read_bio_RSA_PUBKEY( mem , NULL , NULL , NULL );
	BIO_free(mem);

	int rsaprivatesize = RSA_size(rsaprivate);
	int rsapublicsize = RSA_size(rsapublic);
	unsigned char msg[rsapublicsize];
	unsigned char buffer[rsapublicsize];
//========================================================================================================

//===================================reading in and decrypting==============================================================
	cout<<"server step 2"<<endl;
	BIO_read(accept,buffer, sizeof(buffer));//read from client	
	RSA_private_decrypt(sizeof(buffer),(unsigned char *) buffer,msg,rsaprivate,RSA_PKCS1_PADDING);//decrypt and output message
	cout<<msg<<endl;
//===============================================================================================================



//===========================================hashing============================================================

	unsigned char *msg2 = (unsigned char *) msg;
	unsigned char digest[20];
	unsigned char buffer2[rsaprivatesize];

	cout<<"server step 3,4,5:"<<endl;
	SHA1(msg2, sizeof(msg2), digest);
	RSA_private_encrypt(sizeof(digest),(unsigned char *)digest,(unsigned char *)buffer2,rsaprivate,RSA_PKCS1_PADDING);
	//cout<<digest<<endl;	
	BIO_write(accept, buffer2, sizeof(buffer2));

//====================================================================================================================

	
//===========================================recieve the encrypted file name=============================================

	cout<<"server step 6"<<endl;
	//recieve file name
	char encfile[rsapublicsize];
	char buffer3[rsaprivatesize];
	//char rec[200] = {0};
	BIO_read(accept,encfile,sizeof(encfile));
	RSA_private_decrypt(sizeof(encfile),(unsigned char *)encfile,(unsigned char *)buffer3,rsaprivate,RSA_PKCS1_PADDING);
	cout<<"filename:"<<buffer3<<endl;
//=======================================================================================================================


//================================================send file back over=====================================================
	
cout<<"server step 7"<<endl;
	vector<char> sendbacktoclient;
	
	char mander;	
	int i = 0;
	ifstream filestream;
filestream.open(buffer3);

	while(!filestream.eof())
	{
		mander = filestream.get();
		sendbacktoclient.push_back(mander);
	}
		
		char buffer4[sendbacktoclient.size()];
		for(int i =0; i < sendbacktoclient.size(); i++)
			{
					cout<<sendbacktoclient[i];
					buffer4[i]=sendbacktoclient[i];

			}

	BIO_write(accept,buffer4,sizeof(buffer4));	

	cout<<"server step 8: closing connection"<<endl;
	BIO_flush(accept);		
	BIO_free_all(accept);

//==========================================================================================================================

return 0;
}
