#include<stdio.h>
#include<string.h>
#include</usr/include/openssl/rsa.h>
#include</usr/include/openssl/engine.h>
#include</usr/include/openssl/pem.h>
#include</usr/include/openssl/conf.h>
#include</usr/include/openssl/x509v3.h>
#include</usr/include/openssl/bn.h>
#include</usr/include/openssl/evp.h>
#include</usr/include/openssl/err.h>
#include<time.h>
#include</usr/include/openssl/sha.h>



#define hash_outlen 32
#define pub_key_enc_outlen 128 
#define aes_blk_size 16 
#define u_cert_filename "cert.u.pem"
#define u_pkey_filename "priv.key.u.pem"
#define t_pkey_filename "priv.key.t.pem"
#define u_pubkey_filename "pub.key.u.pem"
#define t_pubkey_filename "pub.key.t.pem"
#define LogInitializationType 0
#define ResponseMessageType 1
#define AbnormalCloseType 2

//X0, M0, D0, D1, X1, M1 are taken as defined in Secure Audit Logs to Support Computer Forensics by Bruce Schneier and John Kelsey
//Size of X0 is 4+4+184+32 = 224 bytes 
typedef struct
{
    int p; //protocol step identifier
    int d; //time stamp
    X509 certu; //U's certificate
    char a0[hash_outlen]; //Random Starting point 256 bits;
} X0;

//Size of K0 is 256 bits (or 32 bytes)
//Size of M0 is 4+4+128+352 = 488
typedef struct
{
    int p; //Protocol step identifier
    int id_u; //U's ID
    char pub_key_enc_t[pub_key_enc_outlen];
    // Pub Key Encr 128 bytes or 1024, output of RSA encryption of K0
    char sym_key_enc_k0[pub_key_enc_outlen + (int)sizeof(X0) + aes_blk_size]; 
    // pub Key Encr 1024 O/P of signing + (224*8) = 2816; 2816/8 128 + 224 = 352 (352 is divisible by 16)
} M0;

//Size of D0 is 4+4+4+ 488 = 500
typedef struct
{
    int d; //time stamp
    int dplus; //time stamp
    int id_log; //Log Id
    M0 m0; // Message M0
} D0;

typedef struct
{
    char d_char[256]; // Message M0i
    int w0;
} D1;

//size of X1 is 4+4+32 = 40
typedef struct
{
    int p; //Protocol step identifier
    int id_log; //Log ID
    char hash_x0[hash_outlen]; //Output of hashing X0
} X1;

typedef struct
{
    int p; //protocol step identifier
    int id_t; //T's ID
    char pub_key_enc_u[pub_key_enc_outlen]; //Pub key encrp to K1
    char sym_key_enc_k1[pub_key_enc_outlen + (int)sizeof(X1) + aes_blk_size]; 
    //Pub key encr o/p of signing (1024bits )+ 40*8; = 168 bytes. Rounding off to be divisible by 16 (bytes), we get 176 bytes 
} M1;

typedef struct
{
    int wj;
    char *sym_key_enc_kj_ptr;
    int sym_key_enc_outlen;
    char yj[hash_outlen];
    char zj[hash_outlen];
} LJ_INPUT;

typedef struct
{
    unsigned char kjchar[15];
    int wj;
    unsigned char aj[hash_outlen];
} KJ_INPUT;

typedef struct
{
    unsigned char yminus1[hash_outlen];
    // char sym_key_enc_k0[(int)sizeof(D0)+aes_blk_size];
    int wj;
} YJ_INPUT;

typedef struct
{
    char ajplus1char[15];
    char aj[hash_outlen];
} AJP1_INPUT;

typedef struct
{
    int j;
    int wj;
} QJ;

typedef struct
{
    int p;
    int id_log;
    int f;
    char yf[hash_outlen];
    char zf[hash_outlen];
    QJ *qj;
    int qj_len;
} M2_INPUT;


FILE *logfile;
int curr_log_entry_num = 0;
int fileopen =0;

X509 *read_pem_cert_file(char certname[]);
void hash_sha256(unsigned char intext[], int in_length, int *md_len, unsigned char md_value[]);
void aes_encrypt(unsigned char intext[], int in_length, unsigned char key[],
	unsigned char iv[],unsigned char outbuf_aes[], int *outlen);
void aes_decrypt(unsigned char key[],unsigned char iv[],unsigned char outbuf_aes[], 
	unsigned char outbuf_daes[],int *outlen, int *outdlen);
EVP_PKEY *read_pem_pkey(char pkey_filename[]);
EVP_PKEY *read_pem_pubkey(char pubkey_filename[]);
void rsa_encrypt(unsigned char rsa_intext[], size_t rsa_in_length, EVP_PKEY *rsa_key, 
	unsigned char rsa_out[], size_t *rsa_outlen);
void rsa_decrypt(EVP_PKEY *rsa_dkey, unsigned char rsa_out[], size_t *rsa_outlen, 
	unsigned char rsa_dout[], size_t *rsa_doutlen);
void rsa_sign(unsigned char rsa_intext[], size_t rsa_in_length, EVP_PKEY *rsa_key, 
	unsigned char rsa_out[], size_t *rsa_outlen);
size_t rsa_verify(EVP_PKEY *rsa_dkey, unsigned char rsa_out[], size_t *rsa_outlen, 
	unsigned char rsa_intext[], size_t *rsa_in_length);
void newlog_initx(X0 *x0, X509 *certu);
void newlog_initm(M0 *m0, X0 *x0, unsigned char k0[], EVP_PKEY *pkeyu, EVP_PKEY *pubkeyt, 
	size_t *rsa_outlen, int *sha_md_len_x0, size_t *rsa_sign_outlen_x0, int *outlen_aes_x0);
void newlog_initd(D0 *d0);
int send_entry_t(M0 *m0,EVP_PKEY *pkeyt,EVP_PKEY *pubkeyu, size_t *rsa_outlen_m0, int *sha_md_len_x0, 
	size_t *rsa_sign_outlen_x0, int *outlen_aes_x0, EVP_PKEY *pkeyu, EVP_PKEY *pubkeyti, M1 *m1);

void make_log_entry(unsigned char DJ[], int DJsize, int WJ, unsigned char AJ[],unsigned char YJminus1[], 
	unsigned char YJ_next[],int first_entry, unsigned char AJ_NEXT[]);
void hash_HMAC(unsigned char intext[], int in_length, size_t *md_len, unsigned char md_value[], 
	unsigned char AJ_KEY[]);
void decode_print(int entry, X0 *x0);

void getcommandname(char command_name[], char input_str[]);
void getsecondterm(char command_name[], char input_str[], int commandlen);
void do_exit(void);
void do_closelog(void);
void do_newlog(char second_term[], X0 *x0, M0 *m0, M1 *m1, D0 *d0, unsigned char k0[], 
	EVP_PKEY *pkeyu, EVP_PKEY *pkeyt, EVP_PKEY *pubkeyt, X509 *certu, 
	unsigned char yj_next[], unsigned char aj_next[]);
void do_append(char second_term[], int wj, unsigned char aj_next[], unsigned char yj_next[]);
void do_verify(char second_term[], X0 *x0);
void do_verifylog(X0 *x0);


int main(void)
{

    int i, in_length;
    srand(time(NULL));

    //Initial Variables related to crypto messages
    unsigned char k0[32]; //Random session key gen by U
    //  unsigned char k1[32]; // Random session key gen by T
    int d; //Time stamp
    int d_plus; //time stamp
    int id_log = 0; //Log ID
    char a0[32]; // Random starting point
    int wj; //File type
    char kj[32];
    unsigned char yj_next[hash_outlen];
    unsigned char aj_next[hash_outlen];
    X509 *certu; //U's Certificate
    X509 *certt; //T's Certificate
    EVP_PKEY *pkeyu;
    EVP_PKEY *pubkeyu;
    EVP_PKEY *pkeyt;
    EVP_PKEY *pubkeyt;

    char filename[100];
    certu = read_pem_cert_file(u_cert_filename);
    int curr_log_entry_num;
    pkeyu = read_pem_pkey(u_pkey_filename);
    pkeyt = read_pem_pkey(t_pkey_filename);

    pubkeyu = read_pem_pubkey(u_pubkey_filename);
    pubkeyt = read_pem_pubkey(t_pubkey_filename);


    char input_str[256];
    char *input_parser;
    char command_name[100];
    char second_term[100];
    int j,entry;
    X0 *x0 = (X0 *)(malloc(sizeof(X0)));
    M0 *m0 = (M0 *)(malloc(sizeof(M0)));
    M1 *m1 = (M1 *)(malloc(sizeof(M1)));
    D0 *d0 = (D0 *)(malloc(sizeof(D0)));

    while(1)
    { 
        printf("\n\n");

        printf("Enter a command\n");

        //Input the command
        fgets(input_str, sizeof(input_str),stdin);
        //Get command name
        getcommandname(command_name,input_str);
        //Store length of command name
        int commandlen = strlen(command_name)+1; 
        //Check which command it is

        //exit command
        if(!strcmp(command_name,"exit"))
        {
            do_exit(logfile);
            break;
        }

        //closelog command
        else if(!strcmp(command_name,"closelog"))
        {
            do_closelog(logfile);
        }

        else
        {
            //for everything else, there is an argument. Get that argument 
            getsecondterm(second_term, input_str, commandlen);       

            //If the command is "newlog" do the following
            if(!strcmp(command_name,"newlog"))
            {
                do_newlog(second_term, x0, m0, m1, d0, k0, pkeyu, pkeyt, pubkeyt, certu, yj_next[], aj_next[]);
            } 

            //If the command is "append" do the following
            else if(!strcmp(command_name,"append"))
            {
                do_append(second_term, wj, aj_next, yj_next);
            }

            //If the command is "verify" do the following
            else if(!strcmp(command_name,"verify"))
            {
                do_verify(second_term, x0);
            } 

            else if(!strcmp(command_name,"verifylog"))
            {  
                do_verifylog(x0);
            }

            else
            {
                printf("Wrong command. Try again or type \"exit\" to leave\n");
                continue;
            }


        }//else
            
    } // while(1)
    return 0;
} //main

//Read pem_cert_file to get digital certificate
X509 *read_pem_cert_file(char certname[])
{

    FILE *pvt_t_pem;
    pvt_t_pem = fopen(certname,"r");
    if(pvt_t_pem == NULL)
    {
        printf("Cert File could not be opened\n");
        return NULL;
    }

    X509 *CU;
    CU = PEM_read_X509(pvt_t_pem,NULL,NULL,NULL);
    fclose(pvt_t_pem);
    BIO *bio=BIO_new(BIO_s_mem());

    //  Write a certificate to a BIO:
    PEM_write_bio_X509(bio,CU);
    char *temp = (char*)malloc(bio->num_write+1);

    BIO_read(bio,temp,bio->num_write+1);
    free(temp);
    return CU;
}

//Get private key from pem file
EVP_PKEY *read_pem_pkey(char pkey_filename[])
{
    FILE *pkey_file;
    pkey_file =fopen(pkey_filename,"r");
    if(pkey_file == NULL)
    {
        printf("PKey File could not be opened\n");
        return NULL;
    }
    EVP_PKEY *pvt_key;
    pvt_key = PEM_read_PrivateKey(pkey_file,NULL,NULL,NULL);
    fclose(pkey_file);

    return pvt_key;
}

//Get public key from pem file
EVP_PKEY *read_pem_pubkey(char pubkey_filename[])
{
    FILE *pubkey_file;
    pubkey_file =fopen(pubkey_filename,"r");
    if(pubkey_file == NULL)
    {
        printf("PubKey File could not be opened\n");
        return NULL;
    }
    EVP_PKEY *pub_key;
    pub_key = PEM_read_PUBKEY(pubkey_file,NULL,NULL,NULL);
    fclose(pubkey_file);
    return pub_key;
}

//Generate sha 256 hash digest of intext (size in_length) and store the length and value  of digest in md_len and md_value
void hash_sha256(unsigned char intext[], int in_length, int *md_len, unsigned char md_value[])
{
    fflush(NULL);
    EVP_MD_CTX  *md_ctx;
    EVP_MD *md;
    //   EVP_MD_CTX_init(md_ctx);
    md_ctx = EVP_MD_CTX_create();

    int i = EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);

    if(i ==0)
    {
        printf("EVP digest init failed\n");
        fflush(NULL);
    }
    
    i = EVP_DigestUpdate(md_ctx, intext, in_length);

    if(i ==0)
    {
        printf("EVP digest update failed\n");
        fflush(NULL);
    }

    i = EVP_DigestFinal_ex(md_ctx, md_value, md_len);

    if(i ==0)
    {
        printf("EVP digest update failed\n");
        fflush(NULL);
    }
    
    EVP_MD_CTX_destroy(md_ctx);
    fflush(NULL);


    EVP_cleanup();
    return;
}

//Generate HMAC digest of intext (size in_length) using SHA256 and symmetric key AJ_KEY and store the length and value  of digest in md_len and md_value
void hash_HMAC(unsigned char intext[], int in_length, size_t *md_len, unsigned char md_value[], 
	unsigned char AJ_KEY[])
{
    EVP_MD_CTX  *md_ctx;
    EVP_MD *md;
    int i;
    //   EVP_MD_CTX_init(md_ctx);
    md_ctx = EVP_MD_CTX_create();
   
    EVP_PKEY *key;
    
    key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,NULL,AJ_KEY,hash_outlen);

    if(key ==0)
    {
        printf("EVP keygen failed\n");
        fflush(NULL);
    }
    
    i = EVP_DigestSignInit(md_ctx,NULL,EVP_sha256(), NULL, key);

    if(i ==0)
    {
        printf("EVP digest init failed\n");
        fflush(NULL);
    }

    i = EVP_DigestSignUpdate(md_ctx,intext,in_length);

    if(i ==0)
    {
        printf("EVP digest update failed\n");
        fflush(NULL);
    }
    i = EVP_DigestSignFinal(md_ctx, md_value, md_len);
    if(i ==0)
    {
        printf("EVP digest final failed\n");
        fflush(NULL);
    }
    EVP_MD_CTX_destroy(md_ctx);
    //   printf("Destroyed md_ctx\n");
    fflush(NULL);


    EVP_cleanup();
    return;
}

//Generate AES (symmetric) encryption of intext (size in_length) and store the length and value  of digest in md_len and md_value
void aes_encrypt(unsigned char intext[], int in_length, unsigned char key[],unsigned char iv[],
	unsigned char outbuf_aes[], int *outlen)
{
    EVP_CIPHER_CTX aes_ctx;
    int i,tmplen;
    EVP_CIPHER_CTX_init(&aes_ctx);
    EVP_EncryptInit_ex(&aes_ctx,EVP_aes_256_cbc(), NULL, key, iv);
    if(!EVP_EncryptUpdate(&aes_ctx, outbuf_aes, outlen, intext, in_length))
    {
        //Error
        printf("EVP Encryption Update Error\n");
        return;
    }

    if(!EVP_EncryptFinal_ex(&aes_ctx, outbuf_aes + *outlen, &tmplen))
    {
        // Error 
        printf("EVP Encryption Final Error\n");
        return;
    }

    *outlen = *outlen + tmplen;
    EVP_CIPHER_CTX_cleanup(&aes_ctx);
   
    return;
}

void aes_decrypt(unsigned char key[], unsigned char iv[],unsigned char outbuf_aes[], 
	unsigned char outbuf_daes[],int *outlen, int *outdlen)
{
    int i,tempdlen;
    EVP_CIPHER_CTX aes_dctx;
    EVP_CIPHER_CTX_init(&aes_dctx);
    EVP_DecryptInit_ex(&aes_dctx,EVP_aes_256_cbc(), NULL, key, iv);
    
    if(!EVP_DecryptUpdate(&aes_dctx, outbuf_daes, outdlen, outbuf_aes, *outlen))
    {
        printf("Error_Decrypt_Update\n");
        return;
    }

    
    if(!EVP_DecryptFinal_ex(&aes_dctx, outbuf_daes + *outdlen, &tempdlen))
    {
        // Error 
        printf("Error_Decrypt_Final\n");
    }

    EVP_DecryptFinal_ex(&aes_dctx, outbuf_daes + *outdlen, &tempdlen);
   
    *outdlen = *outdlen + tempdlen;
    EVP_CIPHER_CTX_cleanup(&aes_dctx);
    return;
}

void rsa_encrypt(unsigned char rsa_intext[], size_t rsa_in_length, EVP_PKEY *rsa_key, 
	unsigned char rsa_out[], size_t *rsa_outlen)
{
    EVP_PKEY_CTX *rsa_ctx;
    rsa_ctx = EVP_PKEY_CTX_new(rsa_key,NULL);

    if (EVP_PKEY_encrypt_init(rsa_ctx) <= 0)
    printf("Error occured in new2\n");

    // Determine buffer length 
    if (EVP_PKEY_encrypt(rsa_ctx, NULL, rsa_outlen, rsa_intext, rsa_in_length) <= 0)
    printf("Error occured in new6\n");

    if (EVP_PKEY_encrypt(rsa_ctx, rsa_out, rsa_outlen, rsa_intext, rsa_in_length) <= 0)
    printf("Error occured in new6\n");

    //Encrypted data is outlen bytes written to buffer out 
    free(rsa_ctx);
    return;
}


void rsa_decrypt(EVP_PKEY *rsa_dkey, unsigned char rsa_out[], size_t *rsa_outlen, 
	unsigned char rsa_dout[], size_t *rsa_doutlen)
{
    EVP_PKEY_CTX *rsa_dctx;
    rsa_dctx = EVP_PKEY_CTX_new(rsa_dkey,NULL);
    if (EVP_PKEY_decrypt_init(rsa_dctx) <= 0)
    printf("Error occured in dnew2\n");

    if (EVP_PKEY_decrypt(rsa_dctx, NULL, rsa_doutlen, rsa_out, *rsa_outlen) <= 0)
    printf("Error occured in dnew6\n");

    if (EVP_PKEY_decrypt(rsa_dctx, rsa_dout, rsa_doutlen, rsa_out, *rsa_outlen) <= 0)
    printf("Error occured in dnew6\n");

    // Decrypted data is doutlen bytes written to buffer dout 

    free(rsa_dctx);
    return;
}

void rsa_sign(unsigned char rsa_sign_intext[], size_t rsa_sign_in_length, 
	EVP_PKEY *rsa_sign_key, unsigned char rsa_sign_out[], size_t *rsa_sign_outlen)
{
    EVP_PKEY_CTX *rsa_ctx;
    rsa_ctx = EVP_PKEY_CTX_new(rsa_sign_key,NULL);

    if (EVP_PKEY_sign_init(rsa_ctx) <= 0)
    printf("Error occured in snew2\n");

    if (EVP_PKEY_CTX_set_signature_md(rsa_ctx, EVP_sha256())<=0)
    printf("error occured in snewi\n");

    // Determine buffer length 
    if (EVP_PKEY_sign(rsa_ctx, NULL, rsa_sign_outlen, rsa_sign_intext, rsa_sign_in_length) <= 0)
    printf("Error occured in snew6\n");

    if (EVP_PKEY_sign(rsa_ctx, rsa_sign_out, rsa_sign_outlen, rsa_sign_intext, rsa_sign_in_length) <= 0)
    printf("Error occured in new6\n");

    //Encrypted data is outlen bytes written to buffer out 
    free(rsa_ctx);
    return;
}


size_t rsa_verify(EVP_PKEY *rsa_vkey, unsigned char rsa_sign_out[], size_t *rsa_sign_outlen, 
	unsigned char rsa_sign_intext[], size_t *rsa_sign_in_length)
{
    size_t i;
    EVP_PKEY_CTX *rsa_vctx;
    rsa_vctx = EVP_PKEY_CTX_new(rsa_vkey,NULL);
    if (EVP_PKEY_verify_init(rsa_vctx) <= 0)
    printf("Error occured in dnew2\n");
    if (EVP_PKEY_CTX_set_signature_md(rsa_vctx, EVP_sha256())<=0)
    printf("error occured in snew\n");
    //  if (EVP_PKEY_verify(rsa_vctx, NULL, *rsa_sign_voutlen, rsa_sign_out, *rsa_sign_outlen) <= 0)
    //   printf("Error occured in dnew6\n");

    i = EVP_PKEY_verify(rsa_vctx, rsa_sign_out, *rsa_sign_outlen, rsa_sign_intext, *rsa_sign_in_length);

    // Decrypted data is doutlen bytes written to buffer dut 
    free(rsa_vctx);
    return i;
}

void newlog_initx(X0 *x0, X509 *my_certu)
{
    x0->p = 0; //Protocol ID 0
    x0->d = (int) time(NULL); //time stamp
    memcpy(&(x0->certu), my_certu, (size_t)sizeof(X509));
    RAND_bytes(x0->a0,hash_outlen); //Random a0

    return;
}

int send_entry_t(M0 *m0,EVP_PKEY *pkeyt,EVP_PKEY *pubkeyu, size_t *rsa_outlen_m0, 
	int *sha_md_len_x0, size_t *rsa_sign_outlen_x0, int *outlen_aes_x0, EVP_PKEY *pkeyu, EVP_PKEY *pubkeyt, M1 *m1)
{
    //RSA Decryption of Message m0
    int i;
    M0 *m0_t = (M0 *)malloc(sizeof(M0));
    unsigned char *rsa_dout_m0 = (unsigned char *)malloc(sizeof(unsigned char)*1024);
    size_t *rsa_doutlen_m0 = (size_t *)malloc(sizeof(size_t));
    memcpy(m0_t, m0, (size_t)sizeof(M0));
    rsa_decrypt(pkeyt, m0_t->pub_key_enc_t, rsa_outlen_m0, rsa_dout_m0, rsa_doutlen_m0);

    //performed RSA decryption
    
    //AES Symm Decryption of last term of x0
    unsigned char *outbuf_daes_x0 = (unsigned char *)malloc(sizeof(unsigned char)*(2049*2));
    int *outdlen_x0 = (int *)malloc(sizeof(int));
    unsigned char iv_aes_x0[hash_outlen/2];
    memset(iv_aes_x0, (unsigned char)0 , (size_t)(hash_outlen/2));

    //  printf("assigned memset for aes\n");
    unsigned char *rsa_key_touse = (unsigned char *) malloc(sizeof(unsigned char)*(*rsa_doutlen_m0));
    memcpy(rsa_key_touse,rsa_dout_m0,*rsa_doutlen_m0);
    aes_decrypt(rsa_key_touse, iv_aes_x0, (m0_t->sym_key_enc_k0), outbuf_daes_x0, outlen_aes_x0, outdlen_x0);

    //performed aes decryption of last term

    //Verify Digital sign in x0
    X0 *x0_t = (X0 *)malloc(sizeof(X0));
    memcpy(x0_t, outbuf_daes_x0, (size_t)sizeof(X0));
    unsigned char *rsa_vout_x0 = (unsigned char *)malloc(sizeof(unsigned char)*1024);
    size_t *rsa_voutlen_x0 = (size_t *)malloc(sizeof(size_t));
    unsigned char *rsa_sha_md_value_x0 = (unsigned char *)malloc(sizeof(unsigned char)*EVP_MAX_MD_SIZE);
    int *rsa_sha_md_len_x0 = (int *)malloc(sizeof(int));

    size_t rsa_in_length, verify_val;
    rsa_in_length = sizeof(X0);

    //hashing x0
    hash_sha256((unsigned char *)x0_t,rsa_in_length, rsa_sha_md_len_x0, rsa_sha_md_value_x0);
        
    //Verify RSA sign    
    verify_val = rsa_verify(pubkeyu, (unsigned char *)(outbuf_daes_x0+sizeof(X0)), 
    	rsa_sign_outlen_x0, rsa_sha_md_value_x0, (size_t *)rsa_sha_md_len_x0);
    if(verify_val !=(size_t)1)
    {
        printf("RSA signing not verified\n");
        return;
    }


    //So far we have done everything that the trusted server had to do. Now, the trusted server sends a message back
    unsigned char k1[32];
    X1 *x1 = (X1 *)malloc(sizeof(X1));
    x1->p = 2;
    x1->id_log = 2;
    memcpy(x1->hash_x0,rsa_sha_md_value_x0,*rsa_sha_md_len_x0);
    RAND_bytes(k1,32);

    m1->p = 3;
    m1->id_t = 1;

    unsigned char rsa_out_m1[pub_key_enc_outlen];  //output of PKE with U's public key
    size_t *rsa_outlen_m1 = (size_t *)(malloc(sizeof(size_t))); //Length of PKE 3rd term
    int *sha_md_len_x1 = (int *)malloc(sizeof(int)); //length of output of hash (part of 4th term)
    size_t *rsa_sign_outlen_x1 = (size_t *)(malloc(sizeof(size_t))); //length of output of RSA sign (2nd part of 4th term)
    int *outlen_aes_x1 = (int *)malloc(sizeof(int)); //size of final output of 4th term

    rsa_encrypt(k1,hash_outlen, pubkeyu, rsa_out_m1,rsa_outlen_m1);
    memcpy((m1->pub_key_enc_u),rsa_out_m1,*rsa_outlen_m1);

      //x0 conversion to char array (serialize)
    size_t size_x1 = (size_t)sizeof(X1);
    unsigned char serial_x1[size_x1]; //serial out will store serialized x0
    memcpy(serial_x1,x1,size_x1);

    //  printf("I have done second memcpy\n");
    //Compute hash of x0
    unsigned char *sha_md_value_x1 = (unsigned char *)malloc(sizeof(unsigned char)*EVP_MAX_MD_SIZE); 
    //output of hash that will be signed
    
    unsigned char hash_serial_out_x1[hash_outlen]; //Serialized output of hash

    //hash x1
    hash_sha256(serial_x1,(int)size_x1,sha_md_len_x1,sha_md_value_x1); //output is stored in sha_md_value_x0
   
    //SIGN computation
    unsigned char rsa_sign_out_x1[pub_key_enc_outlen]; //output of RSA sign
    rsa_sign(sha_md_value_x1,*sha_md_len_x1, pkeyt, rsa_sign_out_x1,rsa_sign_outlen_x1);

    size_t size3 = (size_t)sizeof(X1) + *rsa_sign_outlen_x1;
    unsigned char *serial_fullterm = (unsigned char *)malloc(sizeof(unsigned char)*size3); 
    //serial fullterm will store (x0,signx0)

    //Serialize the message
    memcpy(serial_fullterm,x1,size_x1);
    memcpy(serial_fullterm+size_x1, rsa_sign_out_x1, (size_t)*rsa_sign_outlen_x1);

    //Symmetric Encryption of serial_fullterm (Message m1)
    unsigned char *outbuf_aes_x1 = (unsigned char *)malloc(sizeof(unsigned char)*(pub_key_enc_outlen + 
    	size_x1+aes_blk_size));
    unsigned char iv_aes_x1[hash_outlen/2];
    memset(iv_aes_x1, (unsigned char)0 , (size_t)(hash_outlen/2));
    aes_encrypt(serial_fullterm,(int)size3,k1,iv_aes_x1,outbuf_aes_x1,outlen_aes_x1);

    memcpy(m1->sym_key_enc_k1, outbuf_aes_x1, (size_t)*outlen_aes_x1);
    
    //Free pointers
    free(outbuf_aes_x0);
    free(sha_md_value_x0);
    

    M1 *m1_t = (M1 *)malloc(sizeof(M1));
    unsigned char *rsa_dout_m1 = (unsigned char *)malloc(sizeof(unsigned char)*1024);
    size_t *rsa_doutlen_m1 = (size_t *)malloc(sizeof(size_t));
    memcpy(m1_t, m1, (size_t)sizeof(M1));

    //RSA Decryption of message m1
    rsa_decrypt(pkeyu, m1_t->pub_key_enc_u, rsa_outlen_m1, rsa_dout_m1, rsa_doutlen_m1);

    //Symm AES Decryption of last term of m1
    unsigned char *outbuf_daes_x1 = (unsigned char *)malloc(sizeof(unsigned char)*(2049*2));
    int *outdlen_x1 = (int *)malloc(sizeof(int));
    unsigned char iv_aes_x1_[hash_outlen/2];
    memset(iv_aes_x1_, (unsigned char)0 , (size_t)(hash_outlen/2));
    unsigned char *rsa_key_touse1 = (unsigned char *)malloc(sizeof(unsigned char)*(*rsa_doutlen_m1));
    memcpy(rsa_key_touse1,rsa_dout_m1,*rsa_doutlen_m1);
    aes_decrypt(rsa_key_touse1, iv_aes_x1_, (m1_t->sym_key_enc_k1), outbuf_daes_x1, outlen_aes_x1, outdlen_x1);

    //Compute hash of X1
    X1 *x1_t = (X1 *)malloc(sizeof(X1));
    memcpy(x1_t, outbuf_daes_x1, (size_t)sizeof(X1));
    unsigned char *rsa_vout_x1 = (unsigned char *)malloc(sizeof(unsigned char)*1024);
    size_t *rsa_voutlen_x1 = (size_t *)malloc(sizeof(size_t));

    unsigned char *rsa_sha_md_value_x1 = (unsigned char *)malloc(sizeof(unsigned char)*EVP_MAX_MD_SIZE);
    int *rsa_sha_md_len_x1 = (int *)malloc(sizeof(int));

    size_t rsa_in_length1, verify_val1;
    rsa_in_length1 = sizeof(X1);
    hash_sha256((unsigned char *)x1_t,rsa_in_length1, rsa_sha_md_len_x1, rsa_sha_md_value_x1);

   //  Verify RSA digital sign
    verify_val1 = rsa_verify(pubkeyt, (unsigned char *)(outbuf_daes_x1+sizeof(X1)), rsa_sign_outlen_x1, 
    	rsa_sha_md_value_x1, (size_t *)rsa_sha_md_len_x1);

    //FREE ALL MEMORY
    int x = 0;
    free(m0_t);
    free(rsa_dout_m0);
    free(rsa_doutlen_m0);
    free(outbuf_daes_x0);
    free(outdlen_x0);
    free(rsa_key_touse);
    free(x0_t);
    free(rsa_vout_x0);
    free(rsa_voutlen_x0);
    free(rsa_sha_md_value_x0);
    free(rsa_sha_md_len_x0);
    free(x1);
    free(rsa_outlen_m1);
    free(sha_md_len_x1);
    free(rsa_sign_outlen_x1);
    free(outlen_aes_x1);
    free(sha_md_value_x1);
    free(serial_fullterm);
    free(outbuf_aes_x1);
    free(m1_t);
    free(rsa_dout_m1);
    free(rsa_doutlen_m1);
    free(outbuf_daes_x1);
    free(outdlen_x1);
    free(rsa_key_touse1);
    free(x1_t);
    free(rsa_vout_x1);
    free(rsa_voutlen_x1);
    free(rsa_sha_md_value_x1);
    free(rsa_sha_md_len_x1);

    return (int)verify_val1;

}


void newlog_initm(M0 *m0, X0 *x0, unsigned char k0[], EVP_PKEY *pkeyu, EVP_PKEY *pubkeyt, 
	size_t *rsa_outlen_m0, int *sha_md_len_x0, size_t *rsa_sign_outlen_x0, int *outlen_aes_x0)
{
    m0->p = 1;
    m0->id_u = 0;
    // Compute Public key encryption of k0, using T's public key
    unsigned char rsa_out_m0[pub_key_enc_outlen];  //output of PKE

    rsa_encrypt(k0,hash_outlen, pubkeyt, rsa_out_m0,rsa_outlen_m0);
    memcpy((m0->pub_key_enc_t),rsa_out_m0,*rsa_outlen_m0);

    int i;
    for(i=0;i<(int)*rsa_outlen_m0;i++)
    //    printf("%c",rsa_out_m0[i]);
    printf("\n");
    //Compute (x0, SIGNu(x0)

    //x0 conversion to char array (serialize)
    size_t size_x0 = (size_t)sizeof(X0);
    unsigned char serial_x0[size_x0]; //serial out will store serialized x0
    memcpy(serial_x0,x0,size_x0);

    //Compute hash of x0
    unsigned char *sha_md_value_x0 = (unsigned char *)malloc(sizeof(unsigned char)*EVP_MAX_MD_SIZE); //output of hash that will be signed
    
    unsigned char hash_serial_out_x0[hash_outlen]; //Serialized output of hash
    hash_sha256(serial_x0,(int)size_x0,sha_md_len_x0,sha_md_value_x0); //output is stored in sha_md_value_x0

    //SIGN computation
    unsigned char rsa_sign_out_x0[pub_key_enc_outlen]; //output of RSA sign
    rsa_sign(sha_md_value_x0,*sha_md_len_x0, pkeyu, rsa_sign_out_x0,rsa_sign_outlen_x0);

    for(i=0;i<(int)*rsa_sign_outlen_x0;i++)
    printf("%c",rsa_sign_out_x0[i]);
    printf("\n");

    size_t size2 = (size_t)sizeof(X0) + *rsa_sign_outlen_x0;
    unsigned char *serial_fullterm = (unsigned char *) malloc(sizeof(unsigned char)*size2); //serial fullterm will store (x0,signx0)
    memcpy(serial_fullterm,x0,size_x0);
    memcpy(serial_fullterm+size_x0, rsa_sign_out_x0, (size_t)*rsa_sign_outlen_x0);

    //Symmetric Encryption of serial_fullterm
    unsigned char *outbuf_aes_x0 = (unsigned char *)malloc(sizeof(unsigned char)*(pub_key_enc_outlen + 
    	size_x0+aes_blk_size));
    unsigned char iv_aes_x0[hash_outlen/2];
    memset(iv_aes_x0, (unsigned char)0 , (size_t)(hash_outlen/2));
    aes_encrypt(serial_fullterm,(int)size2,k0,iv_aes_x0,outbuf_aes_x0,outlen_aes_x0);


    memcpy(m0->sym_key_enc_k0, outbuf_aes_x0, (size_t)*outlen_aes_x0);
    free(outbuf_aes_x0);
    free(sha_md_value_x0);
    free(serial_fullterm);

    return;
}

void newlog_initd(D0 *d0)
{
    return;
}
char outbuf_des_d[2090];

//DJ: Jth entry, as per protocol; DJsize: Size of the entry; WJ: Entry type; AJ: Jth hash digest of A0; 
//YJminus1: Y(j-1) as per protocol; YJ_next: Yj; first_entry: Is the current entry, the first?; 
//logfile: Name of logfile; AJ_Next: Jth hash of A0
void make_log_entry(unsigned char DJ[], int DJsize, int WJ, unsigned char AJ[],unsigned char YJminus1[], 
	unsigned char YJ_next[],int first_entry, unsigned char AJ_NEXT[])
{
    int i;
    unsigned char *md_value_kj = (unsigned char *)malloc(sizeof(unsigned char)*EVP_MAX_MD_SIZE); 
    int *md_len_kj = (int *)malloc(sizeof(int));
    // HASHING CODE WITH sha256 : KJ
    KJ_INPUT _kjinput;
    KJ_INPUT *kjinput = &_kjinput;
    unsigned char enc_str[] = "Encryption Key";
    memcpy((kjinput->kjchar),enc_str,15);
    kjinput->wj = ResponseMessageType;
    memcpy(kjinput->aj, AJ, hash_outlen);
    unsigned char KJ[sizeof(KJ_INPUT)];
    memcpy(KJ, kjinput, sizeof(KJ_INPUT));

    hash_sha256(KJ,sizeof(KJ_INPUT), md_len_kj, md_value_kj); 

    //HASHING WITH SHA256 : DJ
    unsigned char *md_value_yj = (unsigned char *)malloc(sizeof(unsigned char)*EVP_MAX_MD_SIZE); 
    int *md_len_yj = (int *)malloc(sizeof(int));
    unsigned char iv_aes_yj[hash_outlen/2];
    memset(iv_aes_yj, (unsigned char)0 , (size_t)(hash_outlen/2));
    unsigned char *outbuf_aes_yj = (unsigned char *)malloc(sizeof(unsigned char)*2048);
    int *outlen_aes_yj = (int *)malloc(sizeof(int));

    aes_encrypt(DJ,DJsize,md_value_kj,iv_aes_yj,outbuf_aes_yj,outlen_aes_yj);

    // HASHING CODE WITH sha256  : YJ 
    if(!first_entry)
    {

        unsigned char *YJ = (unsigned char *)malloc(sizeof(unsigned char)*(hash_outlen+(*outlen_aes_yj)+sizeof(int)));

        memcpy(YJ,YJminus1,hash_outlen);
        memcpy(YJ+hash_outlen,outbuf_aes_yj,(*outlen_aes_yj));
        memcpy(YJ+hash_outlen+(*outlen_aes_yj),&(kjinput->wj),sizeof(int));
        hash_sha256(YJ,hash_outlen+(*outlen_aes_yj)+sizeof(int), md_len_yj, md_value_yj);
        free(YJ);
    }
    else
    { 
        unsigned char *YJ = (unsigned char *)malloc(sizeof(unsigned char)*(20+(*outlen_aes_yj)+sizeof(int)));
        unsigned char yjm1[20];
        memset(yjm1,(unsigned char)0,20);
        memcpy(YJ,yjm1,20);
        memcpy(YJ+20,outbuf_aes_yj,(*outlen_aes_yj));
        memcpy(YJ+20+(*outlen_aes_yj),&(kjinput->wj),sizeof(int));
        hash_sha256(YJ,20+(*outlen_aes_yj)+sizeof(int), md_len_yj, md_value_yj);
        free(YJ);
    }


    memcpy(YJ_next, md_value_yj, *md_len_yj);


    unsigned char ZJ[hash_outlen];
    size_t *outlen_zj = (size_t *)malloc(sizeof(size_t));
    hash_HMAC(YJ_next,hash_outlen,outlen_zj,ZJ,AJ);

    //Compute LJ
    //total size  Wj ENC(DJ) HASH YJ-1) HMAC(YJ)
    long int lj_size = sizeof(long int)+sizeof(int)+(*outlen_aes_yj)+(*md_len_yj)+(*outlen_zj);
    unsigned char *LJ = (unsigned char *)malloc(sizeof(unsigned char)*lj_size);
    memcpy(LJ,&lj_size,sizeof(long int));
    memcpy(LJ+sizeof(long int),&(kjinput->wj),sizeof(int));
    memcpy(LJ+sizeof(long int)+sizeof(int),outbuf_aes_yj,(*outlen_aes_yj));
    memcpy(LJ+sizeof(long int)+sizeof(int)+(*outlen_aes_yj),md_value_yj,(*md_len_yj));
    memcpy(LJ+sizeof(long int)+sizeof(int)+(*outlen_aes_yj)+(*md_len_yj),ZJ,(*outlen_zj));

    //Write LJ
    fwrite(LJ,sizeof(unsigned char),lj_size,logfile);

    int *md_len_ajp1 = (int *)malloc(sizeof(int));
    char inc_hash[]= "Incremental Hash";
    char AJ_hashinput[hash_outlen+strlen(inc_hash)];
    memcpy(AJ_hashinput,AJ,hash_outlen);
    memcpy(AJ_hashinput + hash_outlen, inc_hash, strlen(inc_hash));

    //Get AJ
    hash_sha256(AJ_hashinput,(hash_outlen+strlen(inc_hash)), md_len_ajp1, AJ_NEXT);

    //Free pointers
    free(md_len_ajp1);
    free(LJ);
    free(outlen_zj);
    free(outlen_aes_yj);
    free(outbuf_aes_yj);
    free(md_len_yj);
    free(md_value_yj);
    free(md_len_kj);
    free(md_value_kj);

}


//entry: Entry number to verify, logfile: Name of log file, X0 is as per the documentation.
void decode_print(int entry, X0 *x0)
{
    //assume that fseek is already done
    int j,i;
    long int size_j =0;
    long int size_add = 0;
    unsigned char buffer[sizeof(long int)];
    for(j=0;j<=entry;j++)
    {
        fread(buffer, sizeof(unsigned char),sizeof(long int), logfile);
        memcpy(&size_add,buffer,sizeof(long int));
        if(j == entry)
        break;
        size_j+=size_add;
        fseek(logfile,size_j,SEEK_SET);
    }

    //Read entries from log
    unsigned char *verify_string = (unsigned char *)malloc(sizeof(unsigned char) * (size_add-sizeof(long int)));
    fread(verify_string,sizeof(unsigned char),(size_add-sizeof(long int)),logfile);
    long int size_enc_msg;
    size_enc_msg = size_add - (2*hash_outlen) - (sizeof(int)) -(sizeof(long int));
    unsigned char *debug_entry = (unsigned char *)malloc(sizeof(unsigned char)*size_enc_msg);
    memcpy(debug_entry,verify_string+ sizeof(int), size_enc_msg);
    unsigned char a0_initial[hash_outlen];
    memcpy(a0_initial,x0->a0,hash_outlen);
    
    int *md_len_ajpf = (int *)malloc(sizeof(int));
    char inc_hash[]= "Incremental Hash";
    char AJ_hashinput[hash_outlen+strlen(inc_hash)];
    unsigned char *outbuf_daes_d = (unsigned char *)malloc(sizeof(unsigned char)*(2049*2));
    int *outdlen_d = (int *)malloc(sizeof(int));


    //Get the hash "entry" number of times (to verify entry'th entry in the logfile)
    for(j=0;j<=entry;j++)
    {
        memcpy(AJ_hashinput,a0_initial,hash_outlen);
        memcpy(AJ_hashinput + hash_outlen, inc_hash, strlen(inc_hash));
        hash_sha256(AJ_hashinput,(hash_outlen+strlen(inc_hash)), md_len_ajpf, a0_initial);
    }

    unsigned char symmetric_keyneeded[15+sizeof(int)+hash_outlen];
    unsigned char randomest[] = "Encryption Key";
    int wjay = ResponseMessageType;
    memcpy(symmetric_keyneeded,randomest,15);
    memcpy(symmetric_keyneeded+15,&wjay,sizeof(int));
    memcpy(symmetric_keyneeded+19,a0_initial,hash_outlen);
    hash_sha256(symmetric_keyneeded,(hash_outlen+19),md_len_ajpf,a0_initial);


    unsigned char iv_d[hash_outlen/2];
    memset(iv_d,(unsigned char)0,hash_outlen/2);

    //Decrypt the entry
    aes_decrypt(a0_initial, iv_d, debug_entry, outbuf_daes_d, (int *)&size_enc_msg, outdlen_d);

    //Print the decrypted output
    for(j=0;j<(*outdlen_d);j++)
    printf("%s",outbuf_des_d);
    printf("\n");

    //Free pointers
    free(verify_string);
    free(debug_entry);
    free(md_len_ajpf);
    free(outbuf_daes_d);
    free(outdlen_d);
    return; 
}

//main program functions
void getcommandname(char command_name[], char input_str[])
{
    int i=0;
    while((input_str[i] != ' ') && (i<255) && (input_str[i] != '\n'))
    {
        command_name[i] = input_str[i];
        i++;
    }
    command_name[i++] = '\0';    
}

void getsecondterm(char command_name[], char input_str[], int commandlen)
{
    //commandlen is strlen(commandname)+1
    int i = commandlen + 1;

    while((i<255) && (input_str[i] != '\n'))
    {
        second_term[i-(commandlen + 1)] = input_str[i];
        i++;
    }
    
    second_term[i-(commandlen+1)]= '\0';
}

void do_exit(void)
{
    printf("I am exiting\n"); 
    if(fileopen)
    {
        fclose(logfile);
    }

    fileopen = 0;
}

void do_closelog(void)
{
    if(fileopen)
    {
        printf("closing the log %s\n", filename);
        //Write a log entry on the file before closing
        fclose(logfile);

        fileopen = 0;
    }
    else
    printf("No log file open\n");
}

void do_newlog(char second_term[], X0 *x0, M0 *m0, M1 *m1, D0 *d0, unsigned char k0[], EVP_PKEY *pkeyu, 
	EVP_PKEY *pkeyt, EVP_PKEY *pubkeyt, X509 *certu, unsigned char yj_next[], unsigned char aj_next[])
{
    char filename[256]; 
    int wj;

    size_t *rsa_outlen_m0 = (size_t *)(malloc(sizeof(size_t))); //Length of PKE 3rd term
    int *sha_md_len_x0 = (int *)malloc(sizeof(int)); //length of output of hash (part of 4th term)
    size_t *rsa_sign_outlen_x0 = (size_t *)(malloc(sizeof(size_t))); //length of output of RSA sign (2nd part of 4th term)
    int *outlen_aes_x0 = (int *)malloc(sizeof(int)); //size of final output of 4th term

    printf("making a newlog %s\n",second_term);
    fileopen = 1; //NEED TO CHANGE THIS
    curr_log_entry_num = 0;

    //make a new log
    logfile = fopen(second_term,"w+");
    strcpy(filename,second_term);
    if(logfile == 0)
    {
        printf("File ptr cannot be created\n");
        return;
    }
    RAND_bytes(k0,32);
                    
    newlog_initx(x0, certu);
    newlog_initm(m0,x0,k0,pkeyu, pubkeyt, rsa_outlen_m0, sha_md_len_x0, rsa_sign_outlen_x0,outlen_aes_x0);
    d0->d = (int)time(NULL);
    d0->dplus = d+10;
    d0->id_log = 0;
    memcpy(&(d0->m0), m0, sizeof(M0));
              
    //  serilize d0
    unsigned char d0_string[sizeof(D0)];
    memcpy(d0_string,d0,sizeof(D0));
    int size_entry = sizeof(D0);
                
    wj = LogInitializationType;
    make_log_entry(d0_string,size_entry,wj,x0->a0,yj_next,yj_next,1, aj_next);
    curr_log_entry_num++;


    int returnval;
    returnval =  send_entry_t(m0, pkeyt, pubkeyu,rsa_outlen_m0, sha_md_len_x0, 
    	rsa_sign_outlen_x0, outlen_aes_x0, pkeyu, pubkeyt, m1);

    unsigned char m1_string[sizeof(M1)];
    memcpy(m1_string,m1,sizeof(M1));
    size_entry = sizeof(M1);
                
                
    if(returnval ==1)
    {
    //  printf("RSA signing is verified\n");
        wj = ResponseMessageType;
        make_log_entry(m1_string,size_entry,wj,aj_next,yj_next,yj_next,0, aj_next);
        curr_log_entry_num++;
    }
    else
    {
        wj = AbnormalCloseType;
    //  printf("RSA signing not verified\n");
        char abnormal_close[] = "Did not receive m1 correctly";
        make_log_entry(abnormal_close,strlen(abnormal_close),wj,aj_next,yj_next,yj_next,0, aj_next);
        curr_log_entry_num++;
    }

}

void do_append(char second_term[], int wj, unsigned char aj_next[], unsigned char yj_next[])
{
    printf("appending something\n");
    make_log_entry(second_term,strlen(second_term),wj,aj_next,yj_next,yj_next,0, aj_next);
    curr_log_entry_num++;
    return;   
}

void do_verify(char second_term[], X0 *x0)
{
    int entry = atoi(second_term);
    printf("verifying entry number %d\n",entry);
    if(entry ==0 || entry == 1 || entry > curr_log_entry_num++ || fileopen == 0)
    {
        printf("Failed Verification\n");
        return;
    }
    else
    {
        fseek(logfile,0,SEEK_SET);
        decode_print(entry, x0);
    }
}

void do_verifylog(X0 *x0)
{
    int i;

    if(curr_log_entry_num<2)
    {
        printf("Not enough entries to print\n");
    }
    else
    {
        printf("verifying the log\n");
        for(i=2;i<=curr_log_entry_num;i++)
        decode_print(i, x0);
    }
                
}