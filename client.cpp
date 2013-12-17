#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
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
#define data "ganapathi.txt"
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

cout<<"client step 1"<<endl;

	char * server = argv[2];
  char * port = argv[4];

	int err;

	//new context pointer for new connection
  SSL_CTX * ctx = SSL_CTX_new(SSLv23_client_method());
  SSL * ssl;

	//set flags so it doesnt complain
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE,NULL);
	
	//connect and handshake
	BIO *con = BIO_new_ssl_connect(ctx);
	
	BIO_get_ssl(con, &ssl);

	char add[25]={0}; 
	strcat(add,server);
	strcat(add,":");
  strcat(add,port);
	con = BIO_new_connect(add);

  err = BIO_do_connect(con);

  if(err != 1)
    {
      cout<< "connection failed"<<endl;
      exit(1);
    }
	if(BIO_do_handshake(con)<=0)
		{
			cout<< "error connecting";

		}
//=====================================================================================================

//======================================Seeding a random number===========================================
cout<<"client step 2"<<endl;
  srand(time(0));
  int rng = rand()%1000000000+1;
	
	stringstream ss;
	ss<<rng;
	const char * rand = ss.str().c_str();
	
	unsigned char randnumber[sizeof(rand)+1];//make random number array of size random number and then fill it with values of rand
	for(int i = 0; i <sizeof(randnumber); i++)
		{
			randnumber[i] = rand[i];
		}

//=====================================================================================================

//=================================read in public and private keys=======================================
	BIO *mem = NULL;
	RSA *rsaprivate = NULL;

	mem = BIO_new_file("rsaprivatekey.pem", "r");
	rsaprivate = PEM_read_bio_RSAPrivateKey( mem , NULL , NULL , NULL );
	BIO_free(mem);

	mem = NULL;
	RSA *rsapublic = NULL;

	mem = BIO_new_file("rsapublickey.pem", "r");
	rsapublic = PEM_read_bio_RSA_PUBKEY( mem , NULL , NULL , NULL );
	BIO_free(mem);
//========================================================================================================

//============================encrypt the random number  and send it over to the server======================= 
cout<<"client step 3"<<endl;
	unsigned char buf[RSA_size(rsapublic)];	
  RSA_public_encrypt(sizeof(randnumber), (unsigned char *) randnumber,(unsigned char *)buf,rsapublic, RSA_PKCS1_PADDING); //encrypt random number and send it over to the server
  BIO_write(con,buf,sizeof(buf));
	//cout<< rng <<endl;

//========================================================================================================

//==============================================hash unencrypted on client side====================================================
cout<<"client step 4"<<endl;
	unsigned char * randnumber2 = (unsigned char *) randnumber;
	unsigned char digest[20];
	SHA1(randnumber2, sizeof(randnumber2), digest);

//========================================================================================================	
	
//====================================get hashed from server and decrypt it========================================================= 
cout<<"client step 5"<<endl;
	unsigned char buf2[RSA_size(rsapublic)];
	unsigned char msg[RSA_size(rsapublic)];

	BIO_read(con,buf2,sizeof(buf2));
	RSA_public_decrypt(sizeof(msg),(unsigned char *) buf2,(unsigned char *) msg, rsapublic, RSA_PKCS1_PADDING);
	//cout<<msg<<endl;

//========================================================================================================

//============================compare the hash that was unencrypted and the hash from server then request a filename===========================
	

	unsigned char buf3[RSA_size(rsapublic)];
	unsigned char buf4[10000];
	cout<<"client step 6"<<endl;
	if(strncmp((const char*)msg, (const char *) digest,20) == 0) //use string compare to compare if hashes are the same
		{
			cout<<"hashes are the same"<<endl;
			//SEND filename to server
  		char * filename = argv[5];
			cout<<"client step 7"<<endl;
			cout<<filename<<endl;
			RSA_public_encrypt(20,(unsigned char *)filename,(unsigned char *)buf3,rsapublic,RSA_PKCS1_PADDING);
			BIO_write(con,buf3,sizeof(buf3));
			
			//recieve the file from server
			cout<<"client step 8"<<endl;
			BIO_read(con, buf4, sizeof(buf4));
			//cout<<buf4<<endl;
			ofstream ofs("test.txt", std::ofstream::out); //output to test.txt
			ofs<<buf4;
			//display it to text editor
			system("gedit test.txt");
			ofs.close();
		}
	else
		{
			cout<<"compare has failed"<<endl;
		}

//==================================================================================================================================================
	
cout<<"client step 9: closing connections"<<endl;

	BIO_flush(con);		
	BIO_free_all(con);

return 0;
}
