#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>


unsigned char EMSASHA512ID[] = {0x30, 0x51, 0x30, 0x0d,
                                0x06, 0x09, 0x60, 0x86,
                                0x48, 0x01, 0x65, 0x03,
                                0x04, 0x02, 0x03, 0x05,
                                0x00, 0x04, 0x40};

unsigned char EMSASHAID[] =    {0x30, 0x21, 0x30, 0x09,
                                0x06, 0x05, 0x2b, 0x0e,
                                0x03, 0x02, 0x1a, 0x05,
                                0x00, 0x04, 0x14};
enum{
        MAXVALUE = 255,
        ERRLEN = 130,
        RSALEN = 4096/8,
        MAXSIGN = 512,
        MSGLEN = 512,
        IDLEN = 19,
        FIRST = 2,
        INTERMEDIATE = 1,
        TLEN = IDLEN + SHA512_DIGEST_LENGTH,
        PSLEN = RSALEN - SHA512_DIGEST_LENGTH - IDLEN - FIRST - INTERMEDIATE,
        PADLEN = FIRST  + PSLEN + INTERMEDIATE + IDLEN,

        RSALENSHA = 2048/8,
        MAXSIGNSHA = 256,
        IDLENSHA = 15,
        TLENSHA = IDLENSHA + SHA_DIGEST_LENGTH,
        PSLENSHA = RSALENSHA - TLENSHA - FIRST - INTERMEDIATE,
        PADLENSHA = FIRST + PSLENSHA + INTERMEDIATE + IDLENSHA,
};

int debug = 0;
int sha = 0;

void
printHex (unsigned char *data , int lenData)
{
        int i;
        for (i = 0 ; i < lenData ; i++)
            fprintf(stdout , "%02x", data[i]);
        fprintf(stdout, "\nLength %d , %s" , lenData , "\n" );
}

void
printLastError(char *msg)
{
        char * err = malloc(ERRLEN);;

        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr , "%s ERROR: %s\n",msg, err);
        free(err);
        ERR_free_strings();

        exit(1);
}

void printInfo() {
      fprintf(stderr , "%s\n", "If you are using sha mode you must pass keys RSA 2048 bits.");
      fprintf(stderr , "%s\n", "If you are cheking sign you must pass the pubkey whose sign the message.");
      fprintf(stderr , "%s\n", "If you are signing the message you must pass yout private key.");
}


RSA*
getPrivKey (char *privfile , int rsalen)
{
        FILE *fpR;
        RSA *privKey;

        if ((fpR = fopen(privfile , "rb")) == NULL)
                err(1 , "Error opened file : %s" , privfile);

        if ((privKey  = RSA_new()) == NULL)
                printLastError("Error getting private key");

        if ((privKey = PEM_read_RSAPrivateKey(fpR , &privKey , NULL , NULL)) == NULL){
                printInfo();
                printLastError("Error getting private key");
        }

        fclose(fpR);

        if (debug){
            fprintf(stdout, "%s\n", "RSA PRIVKEY READ");
            if (!PEM_write_RSAPrivateKey(stdout , privKey, NULL ,NULL , rsalen , NULL , NULL))
                err(1 , "Error write private key in stdout");
        }
        return privKey;
}


RSA*
getPubkey (char *pubfile)
{
        FILE *fp;
        RSA *pubkey;

        if ((fp = fopen(pubfile , "r")) == NULL)
                err(1 , "Error open file : %s" , pubfile);

        if ((pubkey = RSA_new()) == NULL)
                printLastError("Error Pubkey allocate");

        if ((pubkey = PEM_read_RSA_PUBKEY(fp , &pubkey , NULL , NULL)) == NULL){
                printInfo();
                printLastError("Pubkey read error");
        }

        fclose(fp);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout, "%s\n", "RSA PUBKEY READ");
            if (!PEM_write_RSAPublicKey(stdout , pubkey))
                err(1 , "Error write private key in stdout");
            fprintf(stderr, "%c", '\n');
        }
        return pubkey;
}



void
fsha1(char *fileName , unsigned char *sha1)
{
        SHA_CTX c;
        int fd , nr;
        char buffer[16*1024];    /* Buffer 16 KB */

        if ((fd = open(fileName , O_RDONLY)) < 0)
            err(1 , "Error open file to write : %s" , fileName);

        if (SHA1_Init(&c) == 0)
            err(1 , "Error init SHA512");

        for (;;){
            nr = read(fd , buffer , sizeof buffer);

            if (nr < 0)
                 err(1 , "Error reading file : %s" , fileName);

            if (SHA1_Update(&c , buffer , nr) == 0)
                 err(1 , "SHA512_Update");

            if (nr == 0)
                 break;
        }

        if (SHA1_Update(&c , fileName , strlen(fileName)) == 0)
            err(1 , "SHA512_Update ");


        if (SHA1_Final(sha1 , &c) == 0)
            err(1 , "Error init SHA512");

        close(fd);
}


unsigned char*
getSha1(char *file)
{
        unsigned char *sha1;

        if ((sha1 = malloc(SHA_DIGEST_LENGTH)) == NULL)
            err(1 , "Error keep memory to SHA2 Hash");
        fsha1(file , sha1);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s%s\n", "SHA1 DEBUG FILE :" ,  file);
            printHex(sha1 , SHA_DIGEST_LENGTH);
            fprintf(stderr, "%c", '\n');
        }
        return sha1;
}

void
fsha2(char *fileName , unsigned char *sha2)
{
        SHA512_CTX c;
        int fd , nr;

        /* Buffer 16 KB */
        char buffer[16*1024];

        if ((fd = open(fileName , O_RDONLY)) < 0)
                err(1 , "Error open file to write : %s" , fileName);

        if (SHA512_Init(&c) == 0)
                err(1 , "Error init SHA512");

        for (;;){
            nr = read(fd , buffer , sizeof buffer);

            if (nr < 0)
                err(1 , "Error reading file : %s" , fileName);

            if (SHA512_Update(&c , buffer , nr) == 0)
                err(1 , "SHA512_Update");

            if (nr == 0)
                break;
        }

        if (SHA512_Update(&c , fileName , strlen(fileName)) == 0)
            err(1 , "SHA512_Update ");


        if (SHA512_Final(sha2 , &c) == 0)
            err(1 , "Error init SHA512");

        close(fd);
}


unsigned char*
getSha2(char *file)
{
        unsigned char *sha2;

        if ((sha2 = malloc(SHA512_DIGEST_LENGTH)) == NULL)
            err(1 , "Error keep memory to SHA2 Hash");
        fsha2(file , sha2);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s%s\n", "SHA2 DEBUG FILE :" ,  file);
            printHex(sha2 , SHA512_DIGEST_LENGTH);
            fprintf(stderr, "%c", '\n');
        }
        return sha2;
}

unsigned char*
concatHashID(unsigned char *hash , unsigned char *nameT , int tlen , int idlen , unsigned char *emid)
{
        int i;

        /* First ID */
        for (i = 0 ; i < idlen ; i++)
                nameT[i] = emid[i];

        /* Later T */
        for (i = idlen; i < tlen ; i++)
                nameT[i] = hash[i - idlen];

        return nameT;
}

unsigned char*
getT (unsigned char *hash , int tlen , int idlen ,  unsigned char *emid)
{
        unsigned char *nameT;

        if ((nameT = malloc(tlen)) == NULL)
                err(1 , "Error malloc nameT");

        nameT = concatHashID(hash , nameT , tlen , idlen , emid);
        free(hash);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s\n", "T");
            printHex(nameT , tlen);
            fprintf(stderr, "%c", '\n');
        }
        return nameT;
}


unsigned char*
getMsgToSign (unsigned char *nameT , int msglen , int pslen)
{
        unsigned char *msgToSign;
        int i = 0;

        if ((msgToSign = malloc(msglen)) == NULL)
                err(1 , "Error malloc msgToSign");

        /* PS */
        for (i = 0 ; i < msglen ; i++){
                if (i == 0)
                        msgToSign[i] = 0;

                if (i == 1)
                        msgToSign[i] = 1;

                if (i != 0 && i != 1)
                        msgToSign[i] = MAXVALUE;

                if (i == FIRST + pslen)
                        msgToSign[i] = 0;

                if (i > FIRST + pslen)
                        msgToSign[i] = nameT[i - (FIRST + INTERMEDIATE + pslen)];
        }
        free(nameT);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s\n", "Msg To Sign");
            printHex(msgToSign , msglen);
            fprintf(stderr, "%c", '\n');
        }
        return msgToSign;
}



unsigned char*
signMsg (char *msg , char *privfile , int rsalen , int msglen , int tlen , int idlen ,
              int pslen , unsigned char* emid)
{
        unsigned char *hash;
        unsigned char *nameT;
        unsigned char *msgToSign;
        unsigned char *msgSign;
        RSA *privKey;


        if (!sha)
            /* sha2 in heap */
            hash = getSha2(msg);
        else
            /* sha in heap */
            hash = getSha1(msg);


        /* nameT in heap */
        nameT = getT(hash , tlen , idlen , emid);

        /* msgToSign in heap */
        msgToSign = getMsgToSign(nameT , msglen , pslen);


        if ((msgSign = malloc(msglen)) == NULL)
            err(1 , "Error msg Sign");

        /* msgToSign and msgSign in heap */
        privKey = getPrivKey(privfile , rsalen);

        if ((RSA_private_encrypt(msglen , msgToSign , msgSign , privKey , RSA_NO_PADDING)) < 0){
            printInfo();
            printLastError("Error to sign");
            exit(1);
        }

        /* msgSign in heap */
        free(msgToSign);
        RSA_free(privKey);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout, "%s\n", "MSG SIGNED");
            printHex(msgSign , msglen);
            fprintf(stderr, "%c", '\n');
        }
        return msgSign;
}

void
printSignPEM(char *msg , char *privfile , int rsalen , int msglen , int tlen ,
                  int idlen , int pslen , unsigned char *emid)
{
        BIO *bio;
        BIO *b64;
        unsigned char *msgSign;

        msgSign = signMsg(msg , privfile , rsalen , msglen , tlen , idlen , pslen , emid);

        bio = BIO_new_fp(stdout , BIO_NOCLOSE);
        b64 = BIO_new(BIO_f_base64());
        BIO_push(b64 , bio);

        fprintf(stdout, "---BEGIN SRO SIGNATURE---\n");
        if (BIO_write(b64 , msgSign , msglen) != rsalen)
          err(1, "Error print base64");

        BIO_flush(b64);
        fprintf(stdout, "---END SRO SIGNATURE---\n");

        BIO_free_all(b64);
        free(msgSign);
}

unsigned char*
getSign64 (char *signfile , int msglen)
{
        BIO *bio, *b64;
        unsigned char *msgSign;
        unsigned char inbuf[msglen];
        int inlen , pos , i;


        FILE *fpR;
        if ((fpR = fopen(signfile , "r")) == NULL)
                err(1 , "Error opened sign file : %s" , signfile);

        if ((msgSign = malloc(msglen)) == NULL)
                err(1 , "Error msgSign Validate sign");

        if ((bio = BIO_new_fp(fpR, BIO_NOCLOSE)) == NULL || (b64 = BIO_new(BIO_f_base64())) == NULL)
                err(1 , "Error creating bio");

        BIO_push(b64, bio);

        inlen = 0 , pos = 0;
        while ((inlen = BIO_read(b64, inbuf, msglen)) > 0 && pos < msglen){
                for (i = 0 ; i < inlen ; i++)
                        msgSign[pos + i] = inbuf[i];
                pos += inlen;
        }
        BIO_free_all(b64);
        fclose(fpR);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout, "%s\n", "MESSAGE SIGNED");
            printHex(msgSign , msglen);
            fprintf(stderr, "%c", '\n');
        }
        return msgSign;
}

unsigned char*
getMsg (unsigned char* msgSign , char *pubfile , int msglen)
{
        unsigned char* msg = NULL;
        RSA *pubkey = NULL;
        int result = 0;

        if ((msg = malloc(msglen)) == NULL)
            err(1, "Error msg in getMsg");

        pubkey = getPubkey(pubfile);

        if ((result = RSA_public_decrypt(msglen , msgSign , msg , pubkey , RSA_NO_PADDING)) < 0){
            printInfo();
            printLastError("error decrypting file");
        }

        free(msgSign);
        RSA_free(pubkey);

        if (debug) {
            fprintf(stderr, "%c", '\n');
            fprintf(stdout, "%s\n", "MESSAGE");
            printHex(msg , msglen);
            fprintf(stderr, "%c", '\n');
        }
        return msg;
}


int
rangePS (int pos , int pslen)
{
        return pos > FIRST && pos < pslen + FIRST;
}


int
checkID (int pos , unsigned char *msg , int idlen , unsigned char *emid)
{
        int i , result = 1;

        for (i = 0 ; i < idlen && result ; i++)
            if (msg[pos + i] != emid[i])
                result = 0;

        if (debug) {
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s\n", "ID");
            printHex(emid , idlen);
            fprintf(stderr, "%c", '\n');
        }
        return result;
}


int
checkPadding (unsigned char *msg , int padlen , int pslen , int idlen , unsigned char *emid)
{
        int pos = 0 , result = 1;

        while (pos < padlen && result) {
                if (pos == 0 && msg[pos] != 0)
                        result = 0;

                if (pos == 1 && msg[pos] != 1)
                        result = 0;

                if (rangePS(pos , pslen) && msg[pos] != MAXVALUE)
                        result = 0;

                if (pos == FIRST + pslen && msg[pos] != 0)
                        result = 0;

                if (pos == FIRST + pslen + INTERMEDIATE && !checkID(pos , msg , idlen , emid)){
                      result = 0;
                      pos += idlen;
                }
                pos = pos + 1;
        }

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s\n", "PADDING");
            printHex(msg , padlen);
            fprintf(stderr, "%c", '\n');
        }
        return result;
}

int
checkHash (char *filemsg , unsigned char *msg , int msglen , int padlen)
{
        unsigned char *hashmsg;
        int pos = padlen , result = 1;

        if (!sha)
            /* Get sha 512 of msg*/
            hashmsg = getSha2(filemsg);
        else
            /* Get sha of msg */
            hashmsg = getSha1(filemsg);

        while (pos < msglen && result){
            if (msg[pos] != hashmsg[pos - padlen])
                result = 0;
            pos = pos + 1;
        }
        free(hashmsg);
        return result;
}


void
checkSign(char *filesign64 , char *filemsg  ,  char *pubfile , int msglen , int padlen ,
              int pslen , int idlen , unsigned char *emid)
{
        int check = 1;
        unsigned char *msgSign = NULL , *msg = NULL;

        msgSign = getSign64(filesign64 , msglen);
        msg = getMsg(msgSign , pubfile , msglen);

        if (!checkPadding(msg , padlen , pslen , idlen , emid))
            check = 0;

        if (check && !checkHash(filemsg , msg , msglen , padlen))
            check = 0;

        free(msg);

        if (!check){
            fprintf(stderr, "SIGN FAILURE FILE  : %s\n" , filemsg);
            exit(1);
        }

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stderr, "SIGN ACCEPTED FILE  : %s\n" , filemsg);
            fprintf(stderr, "%c", '\n');
        }
}


int
isVflag (char *parameter)
{
  return strcmp(parameter , "-v") == 0;
}

int
isSflag (char *parameter)
{
  return strcmp(parameter , "-s") == 0;
}

int
isDflag(char *parameter)
{
  return strcmp(parameter , "-d") == 0;
}

int
isDefault (int argc , char *argv[])
{
  return argc == 2 && !isVflag(argv[1]) && !isSflag(argv[1]);
}

int
isOptional(int argc , char *argv[])
{
  return argc == 3 && !isVflag(argv[1]) && isSflag(argv[1]);
}

int
isDefaultDep (int argc , char *argv[])
{
  return argc == 3 && !isVflag(argv[1]) && !isSflag(argv[1]) && isDflag(argv[1]);
}

int
isOptDep (int argc , char *argv[])
{
  return argc == 4 && !isVflag(argv[1]) && ((isSflag(argv[1]) && isDflag(argv[2])) || (isSflag(argv[2]) &&
            isDflag(argv[1])));
}

int
isDefCheck(int argc , char *argv[])
{
  return argc == 4 && isVflag(argv[1]);
}

int
isDefCheckDep (int argc , char *argv[])
{
  return argc == 5 && ((isVflag(argv[1]) && isDflag(argv[2])) || (isVflag(argv[2]) && isDflag(argv[1])));
}

int
isOptCheck (int argc , char *argv[])
{
  return argc == 5 && ((isVflag(argv[1]) && isSflag(argv[2])) || (isVflag(argv[2]) && isSflag(argv[1])));
}

int
isOptCheckDep (int argc , char *argv[])
{
  return argc == 6 && ((isVflag(argv[1]) && isSflag(argv[2]) && isDflag(argv[3])) ||
              (isVflag(argv[3]) && isSflag(argv[1]) && isDflag(argv[2])) ||
              (isVflag(argv[2]) && isSflag(argv[3]) && isDflag(argv[1])));
}

int
main (int argc , char *argv[])
{
        char *filemsg;
        char *privfile;
        char *fileSign64;
        char *pubfile;



        argc--;
        if (argc < 2 && argc > 6){
              /*
              * Bad use of sign.c args
              */
              fprintf(stderr, "Bad Arguments %s\n", argv[0]);
              exit(1);
        }

        sha = 0;
        debug = 0;
        if (isDefault(argc , argv)){
              /*
              * Use with default options print sign with hash sha512
              * only sing the file not verify itself , not debug msgs.
              * The file must be signed with private key RSA 4096 bits.
              */
              sha = 0;
              debug = 0;
              filemsg = argv[1];
              privfile = argv[2];
              printSignPEM(filemsg  , privfile , RSALEN , MAXSIGN , TLEN , IDLEN , PSLEN , EMSASHA512ID);

        } else if (isOptional(argc , argv)){
              /*
              * Use with optional sha print sign with hash sha only sign
              * the file not verify itself , not debug msgs.
              * The file must be signed with a private key RSA 2048 bits.
              */
              sha = 1;
              debug = 0;
              filemsg = argv[2];
              privfile = argv[3];
              printSignPEM(filemsg  , privfile , RSALENSHA , MAXSIGNSHA , TLENSHA , IDLENSHA , PSLENSHA , EMSASHAID);

        } else if (isDefaultDep(argc , argv)) {
              /*
              * Use with default options print sign with hash sha512
              * only sing the file not verify itself , debug msgs.
              * The file must be signed with private key RSA 4096 bits.
              */
              sha = 0;
              debug = 1;
              filemsg = argv[2];
              privfile = argv[3];
              printSignPEM(filemsg  , privfile , RSALEN , MAXSIGN , TLEN , IDLEN , PSLEN , EMSASHA512ID);

        } else if (isOptDep(argc , argv)){
              /*
              * Use with optional sha print sign with hash sha only sign
              * the file not verify itself , debug msgs.
              * The file must be signed with a private key RSA 2048 bits.
              * You can pass the arguments like -s -d or -d -s to debug msgs.
              */
              sha = 1;
              debug = 1;
              filemsg = argv[3];
              privfile = argv[4];
              printSignPEM(filemsg  , privfile , RSALENSHA , MAXSIGNSHA , TLENSHA , IDLENSHA , PSLENSHA , EMSASHAID);

        } else if (isDefCheck(argc , argv)) {
              /*
              * Verify the sign of one file in signed in default mode with
              * private key RSA 4096 and hash sha512. Without debug option.
              */
              debug = 0;
              sha = 0;
              fileSign64 = argv[2];
              filemsg = argv[3];
              pubfile = argv[4];
              checkSign(fileSign64 , filemsg  , pubfile , MAXSIGN , PADLEN , PSLEN , IDLEN , EMSASHA512ID);

        } else  if (isDefCheckDep(argc , argv)) {
              /*
              * Verify the sign of one file in signed in default mode with
              * private key RSA 4096 and hash sha512. With debug option.
              */
              debug = 1;
              sha = 0;
              fileSign64 = argv[3];
              filemsg = argv[4];
              pubfile = argv[5];
              checkSign(fileSign64 , filemsg  ,  pubfile , MAXSIGN , PADLEN , PSLEN , IDLEN , EMSASHA512ID);

        } else if (isOptCheck(argc , argv)) {
              /*
              * Verify the sign of one file signed in optional mode with
              * private key RSA 2048 and hash sha. Without debug option.
              */
              debug = 0;
              sha = 1;
              fileSign64 = argv[3];
              filemsg = argv[4];
              pubfile = argv[5];
              checkSign(fileSign64 , filemsg  , pubfile , MAXSIGNSHA , PADLENSHA , PSLENSHA , IDLENSHA , EMSASHAID);

        } else if (isOptCheckDep(argc , argv)) {
              /*
              * Verify the sign of one file in signed in optional mode with
              * private key RSA 2048 and hash sha. With debug option.
              */
              debug = 1;
              sha = 1;
              fileSign64 = argv[4];
              filemsg = argv[5];
              pubfile = argv[6];
              checkSign(fileSign64 , filemsg  , pubfile , MAXSIGNSHA , PADLENSHA , PSLENSHA , IDLENSHA , EMSASHAID);
        } else {
              fprintf(stderr, "Bad Arguments %s\n", argv[0]);
              exit(1);
        }
        exit(EXIT_SUCCESS);
}
