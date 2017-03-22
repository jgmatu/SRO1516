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

enum{
        MAXVALUE = 255,
        PSFINAL = 3,
        MSGPAD = 3,
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
};

int debug = 0;

void
printHex (unsigned char *data , int lenData)
{
      int i;
      for (i = 0 ; i < lenData ; i++)
          fprintf(stdout , "%02x", data[i]);
      fprintf(stdout, "\n");
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
      fprintf(stderr , "%s\n", "If you are cheking sign you must pass the pubkey whose sign the message.");
      fprintf(stderr , "%s\n", "If you are signing the message you must pass yout private key.");
}

void
hash(char *fileName , unsigned char *sha2)
{
        SHA512_CTX c;
        int fd , nr;
        char buffer[16*1024];    /* Buffer 16 KB */

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
getHash(char *file)
{
        unsigned char *sha2;

        if ((sha2 = malloc(SHA512_DIGEST_LENGTH)) == NULL)
                err(1 , "Error keep memory to SHA2 Hash");
        hash(file , sha2);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s%s\n", "SHA2 DEBUG FILE :" ,  file);
            printHex(sha2 , SHA512_DIGEST_LENGTH);
            fprintf(stderr, "%c", '\n');
        }
        return sha2;
}

unsigned char*
concatHashID (unsigned char *sha2 , unsigned char *nameT)
{
        int i;

        /* First ID */
        for (i = 0 ; i < IDLEN ; i++)
                nameT[i] = EMSASHA512ID[i];

        /* Later T */
        for (i = IDLEN ; i < TLEN ; i++)
                nameT[i] = sha2[i - IDLEN];

        return nameT;
}

unsigned char*
getT (unsigned char *sha2)
{
        unsigned char *nameT;

        if ((nameT = malloc(TLEN)) == NULL)
                err(1 , "Error malloc name_T");

        nameT = concatHashID(sha2 , nameT);

        free(sha2);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s\n", "T");
            printHex(nameT , TLEN);
            fprintf(stderr, "%c", '\n');
        }
        return nameT;
}

unsigned char*
getMsgToSign (unsigned char *nameT)
{
        unsigned char *msgToSign;
        int i = 0;

        if ((msgToSign = malloc(MSGLEN)) == NULL)
                err(1 , "Error malloc msgToSign");


        /* PS */
        for (i = 0 ; i < MSGLEN ; i++){
            if (i == 0)
                msgToSign[i] = 0;

            if (i == 1)
                msgToSign[i] = 1;

            if (i != 0 && i != 1)
                msgToSign[i] = MAXVALUE;

            if (i == FIRST + PSLEN)
                  msgToSign[i] = 0;

            if (i > FIRST + PSLEN)
                  msgToSign[i] = nameT[i - (FIRST + INTERMEDIATE + PSLEN)];
        }
        free(nameT);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s\n", "Msg To Sign");
            printHex(msgToSign , MSGLEN);
            fprintf(stderr, "%c", '\n');
        }
        return msgToSign;
}



RSA*
getPrivKey (char *file)
{
        FILE *fpR;
        RSA *privKey;

        if ((fpR = fopen(file , "rb")) == NULL)
                err(1 , "Error opened file : %s" , file);

        if ((privKey  = RSA_new()) == NULL)
                printLastError("Error getting private key");


        if ((privKey = PEM_read_RSAPrivateKey(fpR , &privKey , NULL , NULL)) == NULL){
              printInfo();
              printLastError("Error getting private key");
        }

        fclose(fpR);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout, "%s\n", "RSA PRIVKEY READ");
            if (!PEM_write_RSAPrivateKey(stdout , privKey, NULL ,NULL , RSALEN , NULL , NULL))
                err(1 , "Error write private key in stdout");
            fprintf(stderr, "%c", '\n');
        }
        return privKey;
}



unsigned char*
signMsg (char *msg , char *privfile)
{
        unsigned char *sha2;
        unsigned char *name_T;
        unsigned char *msgToSign;
        unsigned char *msgSign;
        RSA *privKey;

        sha2 = getHash(msg);
        /* sha2 in heap */

        name_T = getT(sha2);
        /* name_T in heap */

        msgToSign = getMsgToSign(name_T);
        /* msgToSign in heap */

        if ((msgSign = malloc(MSGLEN)) == NULL)
                err(1 , "Error msg Sign");

        privKey = getPrivKey(privfile);
        /* msgToSign and msgSign in heap */


        if ((RSA_private_encrypt(MSGLEN , msgToSign , msgSign , privKey , RSA_NO_PADDING)) < 0){
              printInfo();
              printLastError("Error to sign");
              exit(1);
        }

        free(msgToSign);
        /*msgSing in heap*/
        RSA_free(privKey);


        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout, "%s\n", "MSG SIGNED");
            printHex(msgSign , MSGLEN);
            fprintf(stderr, "%c", '\n');
        }
        return msgSign;
}

void
printSignPEM(char *msg , char *privfile)
{
        BIO *bio;
        BIO *b64;
        unsigned char *msgSign = signMsg(msg , privfile);

        bio = BIO_new_fp(stdout , BIO_NOCLOSE);
        b64 = BIO_new(BIO_f_base64());
        BIO_push(b64 , bio);

        fprintf(stdout, "---BEGIN SRO SIGNATURE---\n");
        if (BIO_write(b64 , msgSign , MSGLEN) != RSALEN)
                err(1, "Error print base64");

        BIO_flush(b64);
        fprintf(stdout, "---END SRO SIGNATURE---\n");

        BIO_free_all(b64);
        free(msgSign);
}


unsigned char*
getSign64 (char *signfile)
{
        BIO *bio, *b64;
        unsigned char *msgSign;
        unsigned char inbuf[MAXSIGN];
        int inlen , pos , i;


        FILE *fpR;
        if ((fpR = fopen(signfile , "r")) == NULL)
                err(1 , "Error opened sign file : %s" , signfile);

        if ((msgSign = malloc(MSGLEN)) == NULL)
                err(1 , "Error msgSign Validate sign");

        if ((bio = BIO_new_fp(fpR, BIO_NOCLOSE)) == NULL || (b64 = BIO_new(BIO_f_base64())) == NULL)
                err(1 , "Error creating bio");

        BIO_push(b64, bio);

        inlen = 0 , pos = 0;
        while ((inlen = BIO_read(b64, inbuf, MAXSIGN)) > 0 && pos < MAXSIGN){
                for (i = 0 ; i < inlen ; i++)
                        msgSign[pos + i] = inbuf[i];
                pos += inlen;
        }

        BIO_free_all(b64);
        fclose(fpR);

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout, "%s\n", "MESSAGE SIGNED");
            printHex(msgSign , MSGLEN);
            fprintf(stderr, "%c", '\n');
        }
        return msgSign;
}


RSA*
getPubkey (char *pubfile)
{
        FILE *fp;
        RSA *pubkey;

        if ((fp = fopen(pubfile , "r")) == NULL)
            err(1 , "Error open file : %s" , pubfile);

        if ((pubkey = RSA_new()) == NULL)
            printLastError("Pubkey allocate");

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

unsigned char*
getMsg (unsigned char* msgSign , char *pubfile)
{
        unsigned char* msg = NULL;
        RSA *pubkey = NULL;
        int result = 0;

        if ((msg = malloc(MSGLEN)) == NULL)
            err(1, "Error msg in getMsg");

        pubkey = getPubkey(pubfile);

        if ((result = RSA_public_decrypt(MSGLEN , msgSign , msg , pubkey , RSA_NO_PADDING)) < 0){
              printInfo();
              printLastError("Error decrypting file");
        }

        free(msgSign);
        RSA_free(pubkey);

        if (debug) {
            fprintf(stderr, "%c", '\n');
            fprintf(stdout, "%s\n", "MESSAGE");
            printHex(msg , MSGLEN);
            fprintf(stderr, "%c", '\n');
        }
        return msg;
}


int
rangePS (int pos)
{
        return pos > FIRST && pos < PSLEN + FIRST;
}


int
checkID (int pos , unsigned char *msg)
{
        int i , result = 1;

        for (i = 0 ; i < IDLEN && result ; i++)
            if (msg[pos + i] != EMSASHA512ID[i])
                result = 0;

        if (debug) {
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s\n", "ID");
            printHex(EMSASHA512ID , IDLEN);
            fprintf(stderr, "%c", '\n');
        }
        return result;
}


int
checkPadding (unsigned char *msg)
{
        int pos = 0 , result = 1;

        while (pos < PADLEN && result) {
            if (pos == 0 && msg[pos] != 0)
                  result = 0;

            if (pos == 1 && msg[pos] != 1)
                  result = 0;

            if (rangePS(pos) && msg[pos] != MAXVALUE)
                  result = 0;

            if (pos == FIRST + PSLEN && msg[pos] != 0)
                  result = 0;

            if (pos == FIRST + PSLEN + INTERMEDIATE && !checkID(pos , msg)){
                  result = 0;
                  pos += IDLEN;
            }
            pos = pos + 1;
        }

        if (debug){
            fprintf(stderr, "%c", '\n');
            fprintf(stdout , "%s\n", "PADDING");
            printHex(msg , PADLEN);
            fprintf(stderr, "%c", '\n');
        }
        return result;
}

int
checkHash (char *filemsg , unsigned char *msg)
{
        unsigned char *hashmsg = getHash(filemsg);
        int pos = PADLEN , result = 1;

        while (pos < MSGLEN && result){
            if (msg[pos] != hashmsg[pos - PADLEN])
                    result = 0;
            pos = pos + 1;
        }
        free(hashmsg);
        return result;
}

void
checkSign(char *filesign64 , char *filemsg  ,  char *pubfile )
{
        int check = 1;
        unsigned char *msgSign = NULL , *msg = NULL;

        msgSign = getSign64(filesign64);
        msg = getMsg(msgSign , pubfile);


        if (!checkPadding(msg))
            check = 0;


        if (check && !checkHash(filemsg , msg))
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
isDflag(char *parameter)
{
  return strcmp(parameter , "-d") == 0;
}

int
isDefault (int argc , char *argv[])
{
  return argc == 2 && !isVflag(argv[1]);
}

int
isDefaultDep (int argc , char *argv[])
{
  return argc == 3 && !isVflag(argv[1]) && isDflag(argv[1]);
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
main (int argc , char *argv[])
{
        char *filemsg;
        char *privfile;
        char *filesign64;
        char *pubfile;

        argc--;
        if (argc < 2 && argc > 5){
              /* Bad use of sign.c args */
              fprintf(stderr, "Bad Arguments %s\n", argv[0]);
              exit(1);
        }

        debug = 0;
        /* Use with default print sign */
        if (isDefault(argc , argv)) {
              /*
              * Use with default options print sign with hash sha512
              * only sing the file not verify itself , not debug msgs.
              * The file must be signed with private key RSA 4096 bits.
              */
              debug = 0;
              filemsg = argv[1];
              privfile = argv[2];
              printSignPEM(filemsg , privfile);

        } else if (isDefaultDep(argc , argv)) {
              /*
              * Use with default options print sign with hash sha512
              * only sing the file not verify itself , debug msgs.
              * The file must be signed with private key RSA 4096 bits.
              */
              debug = 1;
              filemsg = argv[2];
              privfile = argv[3];
              printSignPEM(filemsg , privfile);

        } else if (isDefCheck(argc , argv)) {
              /*
              * Verify the sign of one file in signed in default mode with
              * private key RSA 4096 and hash sha512. Without debug option.
              */
              debug = 0;
              filesign64 = argv[2];
              filemsg = argv[3];
              pubfile = argv[4];
              checkSign(filesign64 , filemsg  , pubfile);

        } else if (isDefCheckDep(argc , argv)) {
              /*
              * Verify the sign of one file in signed in default mode with
              * private key RSA 4096 and hash sha512. With debug option.
              */
              debug = 1;
              filesign64 = argv[3];
              filemsg = argv[4];
              pubfile = argv[5];
              checkSign(filesign64 , filemsg  , pubfile);

        } else {
              fprintf(stderr, "Bad Arguments %s\n", argv[0]);
              exit(1);
        }
        exit(EXIT_SUCCESS);
}
