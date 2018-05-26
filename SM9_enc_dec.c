/************************************************************************
File name: SM9_enc_dec.c
Author:Owen Liu
Notes:
**************************************************************************/
#include "SM9_enc_dec.h"
#include "kdf.h"
#include "SM4.h"
/****************************************************************
Function: bytes128_to_ecn2
Description: convert 128 bytes into ecn2
Calls: MIRACL functions
Called By: SM9_Init,SM9_Decrypt
Input: Ppubs[]
Output: ecn2 *res
Return: FALSE: execution error
TRUE: execute correctly
Others:
****************************************************************/
void my_char_cat(char *a, char *b, int len,int start)
{
	a += start;
	while (len) {
		*a = *b;
		a++;
		b++;
		len--;
	}
}
BOOL bytes128_to_ecn2(unsigned char Ppubs[], ecn2 *res)
{
	zzn2 x, y;
	big a, b;
	ecn2 r;
	r.x.a = mirvar(0); r.x.b = mirvar(0);
	r.y.a = mirvar(0); r.y.b = mirvar(0);
	r.z.a = mirvar(0); r.z.b = mirvar(0);
	r.marker = MR_EPOINT_INFINITY;
	x.a = mirvar(0); x.b = mirvar(0);
	y.a = mirvar(0); y.b = mirvar(0);
	a = mirvar(0); b = mirvar(0);
	bytes_to_big(BNLEN, Ppubs, b);
	bytes_to_big(BNLEN, Ppubs + BNLEN, a);
	zzn2_from_bigs(a, b, &x);
	bytes_to_big(BNLEN, Ppubs + BNLEN * 2, b);
	bytes_to_big(BNLEN, Ppubs + BNLEN * 3, a);
	zzn2_from_bigs(a, b, &y);
	return ecn2_set(&x, &y, res);
}
/****************************************************************
Function: zzn12_ElementPrint
Description: print all element of struct zzn12
Calls: MIRACL functions
Called By: SM9_Encrypt,SM9_Decrypt
Input: zzn12 x
Output: NULL
Return: NULL
Others:
****************************************************************/
void zzn12_ElementPrint(zzn12 x)
{
	big tmp;
	tmp = mirvar(0);
	redc(x.c.b.b, tmp); cotnum(tmp, stdout);
	redc(x.c.b.a, tmp); cotnum(tmp, stdout);
	redc(x.c.a.b, tmp); cotnum(tmp, stdout);
	redc(x.c.a.a, tmp); cotnum(tmp, stdout);
	redc(x.b.b.b, tmp); cotnum(tmp, stdout);
	redc(x.b.b.a, tmp); cotnum(tmp, stdout);
	redc(x.b.a.b, tmp); cotnum(tmp, stdout);
	redc(x.b.a.a, tmp); cotnum(tmp, stdout);
	redc(x.a.b.b, tmp); cotnum(tmp, stdout);
	redc(x.a.b.a, tmp); cotnum(tmp, stdout);
	redc(x.a.a.b, tmp); cotnum(tmp, stdout);
	redc(x.a.a.a, tmp); cotnum(tmp, stdout);
}
/****************************************************************
Function: ecn2_Bytes128_Print
Description: print 128 bytes of ecn2
Calls: MIRACL functions
Called By: SM9_Encrypt,SM9_Decrypt
Input: ecn2 x
Output: NULL
Return: NULL
Others:
****************************************************************/
void ecn2_Bytes128_Print(ecn2 x)
{
	big tmp;
	tmp = mirvar(0);
	redc(x.x.b, tmp); cotnum(tmp, stdout);
	redc(x.x.a, tmp); cotnum(tmp, stdout);
	redc(x.y.b, tmp); cotnum(tmp, stdout);
	redc(x.y.a, tmp); cotnum(tmp, stdout);
}
/****************************************************************
Function: LinkCharZzn12
Description: link two different types(unsigned char and zzn12)to one(unsigned char)
Calls: MIRACL functions
Called By: SM9_Encrypt,SM9_Decrypt
Input: message:
len: length of message
w: zzn12 element
Output: Z: the characters array stored message and w
Zlen: length of Z
Return: NULL
Others:
****************************************************************/
void LinkCharZzn12(unsigned char *message, int len, zzn12 w, unsigned char *Z, int Zlen)
{
	big tmp;
	tmp = mirvar(0);
	memcpy(Z, message, len);
	redc(w.c.b.b, tmp); big_to_bytes(BNLEN, tmp, Z + len, 1);
	redc(w.c.b.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN, 1);
	redc(w.c.a.b, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 2, 1);
	redc(w.c.a.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 3, 1);
	redc(w.b.b.b, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 4, 1);
	redc(w.b.b.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 5, 1);
	redc(w.b.a.b, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 6, 1);
	redc(w.b.a.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 7, 1);
	redc(w.a.b.b, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 8, 1);
	redc(w.a.b.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 9, 1);
	redc(w.a.a.b, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 10, 1);
	redc(w.a.a.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 11, 1);
}
/****************************************************************
Function: Test_Point
Description: test if the given point is on SM9 curve
Calls:
Called By: SM9_Decrypt
Input: point
Output: null
Return: 0: success
1: not a valid point on curve
Others:
****************************************************************/
int Test_Point(epoint* point)
{
	big x, y, x_3, tmp;
	epoint *buf;
	x = mirvar(0); y = mirvar(0);
	x_3 = mirvar(0);
	tmp = mirvar(0);
	buf = epoint_init();
	//test if y^2=x^3+b
	epoint_get(point, x, y);
	power(x, 3, para_q, x_3); //x_3=x^3 mod p
	multiply(x, para_a, x);
	divide(x, para_q, tmp);
	add(x_3, x, x); //x=x^3+ax+b
	add(x, para_b, x);
	divide(x, para_q, tmp); //x=x^3+ax+b mod p
	power(y, 2, para_q, y); //y=y^2 mod p
	if (mr_compare(x, y) != 0)
		return 1;
	//test infinity
	ecurve_mult(N, point, buf);
	if (point_at_infinity(buf) == FALSE)
		return 1;
	return 0;
}
/****************************************************************
Function: Test_Range
Description: test if the big x belong to the range[1,n-1]
Calls:
Called By: SM9_Verify
Input: big x ///a miracl data type
Output: null
Return: 0: success
1: x==n,fail
Others:
****************************************************************/
int Test_Range(big x)
{
	big one, decr_n;
	one = mirvar(0);
	decr_n = mirvar(0);
	convert(1, one);
	decr(N, 1, decr_n);
	if ((mr_compare(x, one) < 0) | (mr_compare(x, decr_n) > 0))
		return 1;
	return 0;
}
/***************************************************************
Function: SM4_Block_Encrypt
Description: encrypt the message with padding,according to PKS#5
Calls: SM4_Encrypt
Called By: SM9_Encrypt
Input:
key:the key of SM4
message:data to be encrypted
mlen: the length of message
Output:
cipher: ciphertext
cipher_len:the length of ciphertext
Return: NULL
Others:
****************************************************************/
void SM4_Block_Encrypt(unsigned char key[], unsigned char * message, int mlen, unsigned char *cipher, int * cipher_len)
{
	unsigned char mess[16];
	int i, rem = mlen % 16;
	for (i = 0; i < mlen / 16; i++)
		SM4_Encrypt(key, &message[i * 16], &cipher[i * 16]);
	//encrypt the last block
	memset(mess, 16 - rem, 16);
	if (rem)
		memcpy(mess, &message[i * 16], rem);
	SM4_Encrypt(key, mess, &cipher[i * 16]);
}
/***************************************************************
Function: SM4_Block_Decrypt
Description: decrypt the cipher with padding,according to PKS#5
Calls: SM4_Decrypt
Called By: SM9_Decrypt
Input:
key:the key of SM4
cipher: ciphertext
mlen: the length of ciphertext
Output:
plain: plaintext
plain_len:the length of plaintext
Return: NULL
Others:
****************************************************************/
void SM4_Block_Decrypt(unsigned char key[], unsigned char *cipher, int len, unsigned char *plain, int *plain_len)
{
	int i;
	for (i = 0; i < len / 16; i++)
		SM4_Decrypt(key, cipher + i * 16, plain + i * 16);
	*plain_len = len - plain[len - 1];
}
/****************************************************************
Function: SM9_H1
Description: function H1 in SM9 standard 5.4.2.2
Calls: MIRACL functions,SM3_KDF
Called By: SM9_Encrypt
Input: Z:
Zlen:the length of Z
n:Frobniues constant X
Output: h1=H1(Z,Zlen)
Return: 0: success;
1: asking for memory error
Others:
****************************************************************/
int SM9_H1(unsigned char Z[], int Zlen, big n, big h1)
{
	int hlen, i, ZHlen;
	big hh, i256, tmp, n1;
	unsigned char *ZH = NULL, *ha = NULL;
	hh = mirvar(0); i256 = mirvar(0);
	tmp = mirvar(0); n1 = mirvar(0);
	convert(1, i256);
	ZHlen = Zlen + 1;
	hlen = (int)ceil((5.0*logb2(n)) / 32.0);
	decr(n, 1, n1);
	ZH = (char *)malloc(sizeof(char)*(ZHlen + 1));
	if (ZH == NULL) return SM9_ASK_MEMORY_ERR;
	memcpy(ZH + 1, Z, Zlen);
	ZH[0] = 0x01;
	ha = (char *)malloc(sizeof(char)*(hlen + 1));
	if (ha == NULL) return SM9_ASK_MEMORY_ERR;
	SM3_KDF(ZH, ZHlen, hlen, ha);
	for (i = hlen - 1; i >= 0; i--)//key[从大到小]
	{
		premult(i256, ha[i], tmp);
		add(hh, tmp, hh);
		premult(i256, 256, i256);
		divide(i256, n1, tmp);
		divide(hh, n1, tmp);
	}
	incr(hh, 1, h1);
	free(ZH); free(ha);
	return 0;
}
/****************************************************************
Function: SM9_H2
Description: function H2 in SM9 standard 5.4.2.3
Calls: MIRACL functions,SM3_KDF
Called By: SM9_Sign,SM9_Verify
Input: Z:
Zlen:the length of Z
n:Frobniues constant X
Output: h2=H2(Z,Zlen)
Return: 0: success;
1: asking for memory error
Others:
****************************************************************/
int SM9_H2(unsigned char Z[], int Zlen, big n, big h2)
{
	int hlen, ZHlen, i;
	big hh, i256, tmp, n1;
	unsigned char *ZH = NULL, *ha = NULL;
	hh = mirvar(0); i256 = mirvar(0);
	tmp = mirvar(0); n1 = mirvar(0);
	convert(1, i256);
	ZHlen = Zlen + 1;
	hlen = (int)ceil((5.0*logb2(n)) / 32.0);
	decr(n, 1, n1);
	ZH = (char *)malloc(sizeof(char)*(ZHlen + 1));
	if (ZH == NULL) return SM9_ASK_MEMORY_ERR;
	memcpy(ZH + 1, Z, Zlen);
	ZH[0] = 0x02;
	ha = (char *)malloc(sizeof(char)*(hlen + 1));
	if (ha == NULL) return SM9_ASK_MEMORY_ERR;
	SM3_KDF(ZH, ZHlen, hlen, ha);
	for (i = hlen - 1; i >= 0; i--)//key[从大到小]
	{
		premult(i256, ha[i], tmp);
		add(hh, tmp, hh);
		premult(i256, 256, i256);
		divide(i256, n1, tmp);
		divide(hh, n1, tmp);
	}
	incr(hh, 1, h2);
	free(ZH); free(ha);
	return 0;
}
/****************************************************************
Function: SM9_Enc_MAC
Description: MAC in SM9 standard 5.4.5
Calls: SM3_256
Called By: SM9_Encrypt,SM9_Decrypt
Input:
K:key
Klen:the length of K
M:message
Mlen:the length of message
Output: C=MAC(K,Z)
Return: 0: success;
1: asking for memory error
Others:
****************************************************************/
int SM9_Enc_MAC(unsigned char *K, int Klen, unsigned char *M, int Mlen, unsigned char C[])
{
	unsigned char *Z = NULL;
	int len = Klen + Mlen;
	Z = (char *)malloc(sizeof(char)*(len + 1));
	if (Z == NULL) return SM9_ASK_MEMORY_ERR;
	memcpy(Z, M, Mlen);
	memcpy(Z + Mlen, K, Klen);
	SM3_256(Z, len, C);
	free(Z);
	return 0;
}
/****************************************************************
Function: SM9_Init
Description: Initiate SM9 curve
Calls: MIRACL functions
Called By: SM9_SelfCheck
Input: null
Output: null
Return: 0: success;
5: base point P1 error
6: base point P2 error
Others:
****************************************************************/
int SM9_Init()
{
	big P1_x, P1_y;
	mip = mirsys(1000, 16);;
	mip->IOBASE = 16;
	para_q = mirvar(0); N = mirvar(0);
	P1_x = mirvar(0); P1_y = mirvar(0);
	para_a = mirvar(0);
	para_b = mirvar(0); para_t = mirvar(0);
	X.a = mirvar(0); X.b = mirvar(0);
	P2.x.a = mirvar(0); P2.x.b = mirvar(0);
	P2.y.a = mirvar(0); P2.y.b = mirvar(0);
	P2.z.a = mirvar(0); P2.z.b = mirvar(0);
	P2.marker = MR_EPOINT_INFINITY;
	P1 = epoint_init();
	bytes_to_big(BNLEN, SM9_q, para_q);
	bytes_to_big(BNLEN, SM9_P1x, P1_x);
	bytes_to_big(BNLEN, SM9_P1y, P1_y);
	bytes_to_big(BNLEN, SM9_a, para_a);
	bytes_to_big(BNLEN, SM9_b, para_b);
	bytes_to_big(BNLEN, SM9_N, N);
	bytes_to_big(BNLEN, SM9_t, para_t);
	mip->TWIST = MR_SEXTIC_M;
	ecurve_init(para_a, para_b, para_q, MR_PROJECTIVE); //Initialises GF(q) elliptic curve
	//MR_PROJECTIVE specifying projective coordinates
	if (!epoint_set(P1_x, P1_y, 0, P1)) return SM9_G1BASEPOINT_SET_ERR;
	if (!(bytes128_to_ecn2(SM9_P2, &P2))) return SM9_G2BASEPOINT_SET_ERR;
	set_frobenius_constant(&X);
	return 0;
}
/***************************************************************
Function: SM9_GenerateEncryptKey
Description: Generate encryption keys(public key and private key)
Calls: MIRACL functions,SM9_H1,xgcd,ecn2_Bytes128_Print
Called By: SM9_SelfCheck
Input: hid:0x03
ID:identification
IDlen:the length of ID
ke:master private key used to generate encryption public key and private key
Output: Ppubs:encryption public key
deB: encryption private key
Return: 0: success;
1: asking for memory error
Others:
****************************************************************/
int SM9_GenerateEncryptKey(unsigned char hid[], unsigned char *ID, int IDlen, big ke, unsigned char Ppubs[], unsigned char deB[])
{
	big h1, t1, t2, rem, xPpub, yPpub, tmp;
	unsigned char *Z = NULL;
	int Zlen = IDlen + 1, buf;
	ecn2 dEB;
	epoint *Ppub;
	h1 = mirvar(0); t1 = mirvar(0);
	t2 = mirvar(0); rem = mirvar(0); tmp = mirvar(0);
	xPpub = mirvar(0); yPpub = mirvar(0);
	Ppub = epoint_init();
	dEB.x.a = mirvar(0); dEB.x.b = mirvar(0); dEB.y.a = mirvar(0); dEB.y.b = mirvar(0);
	dEB.z.a = mirvar(0); dEB.z.b = mirvar(0); dEB.marker = MR_EPOINT_INFINITY;
	Z = (char *)malloc(sizeof(char)*(Zlen + 1));
	memcpy(Z, ID, IDlen);
	memcpy(Z + IDlen, hid, 1);
	buf = SM9_H1(Z, Zlen, N, h1);
	if (buf != 0) return buf;
	add(h1, ke, t1);//t1=H1(IDA||hid,N)+ks
	xgcd(t1, N, t1, t1, t1);//t1=t1(-1)
	multiply(ke, t1, t2); divide(t2, N, rem);//t2=ks*t1(-1)
	//Ppub=[ke]P2
	ecurve_mult(ke, P1, Ppub);
	//deB=[t2]P2
	ecn2_copy(&P2, &dEB);
	ecn2_mul(t2, &dEB);
	printf("\n**************The private key deB = (xdeB, ydeB)：*********************\n");
	ecn2_Bytes128_Print(dEB);
	printf("\n**********************PublicKey Ppubs=[ke]P1：*************************\n");
	epoint_get(Ppub, xPpub, yPpub);
	cotnum(xPpub, stdout); cotnum(yPpub, stdout);
	epoint_get(Ppub, xPpub, yPpub);
	big_to_bytes(BNLEN, xPpub, Ppubs, 1);
	big_to_bytes(BNLEN, yPpub, Ppubs + BNLEN, 1);
	redc(dEB.x.b, tmp); big_to_bytes(BNLEN, tmp, deB, 1);
	redc(dEB.x.a, tmp); big_to_bytes(BNLEN, tmp, deB + BNLEN, 1);
	redc(dEB.y.b, tmp); big_to_bytes(BNLEN, tmp, deB + BNLEN * 2, 1);
	redc(dEB.y.a, tmp); big_to_bytes(BNLEN, tmp, deB + BNLEN * 3, 1);
	free(Z);
	return 0;
}
/****************************************************************
Function: SM9_Encrypt
Description: SM9 encryption algorithm
Calls: MIRACL functions,zzn12_init(),ecap(),member(),zzn12_ElementPrint(),
zzn12_pow(),LinkCharZzn12(),SM3_KDF(),SM9_Enc_MAC(),SM4_Block_Encrypt()
Called By: SM9_SelfCheck()
Input:
hid:0x03
IDB //identification of userB
message //the message to be encrypted
len //the length of message
rand //a random number K lies in [1,N-1]
EncID //encryption identification,0:stream cipher 1:block cipher
k1_len //the byte length of K1 in block cipher algorithm
k2_len //the byte length of K2 in MAC algorithm
Ppubs //encrtption public key
Output: C //cipher C1||C3||C2
Clen //the byte length of C
Return:
0: success
1: asking for memory error
2: element is out of order q
3: R-ate calculation error
A: K1 equals 0
Others:
****************************************************************/
int SM9_Encrypt(unsigned char hid[], unsigned char *IDB, unsigned char *message, int mlen, unsigned char rand[],
	int EncID, int k1_len, int k2_len, unsigned char Ppub[], unsigned char C[], int *C_len)
{
	big h, x, y, r;
	zzn12 g, w;
	epoint *Ppube, *QB, *C1;
	unsigned char *Z = NULL, *K = NULL, *C2 = NULL, C3[SM3_len / 8];
	int i = 0, j = 0, Zlen, buf, klen, C2_len;
	//initiate
	h = mirvar(0); r = mirvar(0); x = mirvar(0); y = mirvar(0);
	QB = epoint_init(); Ppube = epoint_init(); C1 = epoint_init();
	zzn12_init(&g); zzn12_init(&w);
	bytes_to_big(BNLEN, Ppub, x);
	bytes_to_big(BNLEN, Ppub + BNLEN, y);
	epoint_set(x, y, 0, Ppube);
	//Step1:calculate QB=[H1(IDB||hid,N)]P1+Ppube
	Zlen = strlen(IDB) + 1;
	Z = (char *)malloc(sizeof(char)*(Zlen + 1));
	if (Z == NULL) return SM9_ASK_MEMORY_ERR;
	memcpy(Z, IDB, strlen(IDB));
	memcpy(Z + strlen(IDB), hid, 1);
	buf = SM9_H1(Z, Zlen, N, h);
	if (buf) return buf;
	ecurve_mult(h, P1, QB);
	ecurve_add(Ppube, QB);
	printf("\n*******************QB:=[H1(IDB||hid,N)]P1+Ppube*****************\n");
	epoint_get(QB, x, y);
	cotnum(x, stdout); cotnum(y, stdout);
	//Step2:randnom
	bytes_to_big(BNLEN, rand, r);
	printf("\n***********************randnum r:********************************\n");
	cotnum(r, stdout);
	//Step3:C1=[r]QB
	ecurve_mult(r, QB, C1);
	printf("\n*************************:C1=[r]QB*******************************\n");
	epoint_get(C1, x, y);
	cotnum(x, stdout); cotnum(y, stdout);
	big_to_bytes(BNLEN, x, C, 1); big_to_bytes(BNLEN, y, C + BNLEN, 1);
	//Step4:g = e(P2, Ppub-e)
	if (!ecap(P2, Ppube, para_t, X, &g)) return SM9_MY_ECAP_12A_ERR;
	//test if a ZZn12 element is of order q
	if (!member(g, para_t, X)) return SM9_MEMBER_ERR;
	printf("\n***********************g=e(P2,Ppube):****************************\n");
	zzn12_ElementPrint(g);
	//Step5:calculate w=g^r
	w = zzn12_pow(g, r);
	printf("\n***************************w=g^r:**********************************\n");
	zzn12_ElementPrint(w);
	free(Z);
	//Step6:calculate C2
	if (EncID == 0)
	{
		C2_len = mlen;
		*C_len = BNLEN * 2 + SM3_len / 8 + C2_len;
		//Step:6-1: calculate K=KDF(C1||w||IDB,klen)
		klen = mlen + k2_len;
		Zlen = strlen(IDB) + BNLEN * 14;
		Z = (char *)malloc(sizeof(char)*(Zlen + 1));
		K = (char *)malloc(sizeof(char)*(klen + 1));
		C2 = (char *)malloc(sizeof(char)*(mlen + 1));
		if (Z == NULL || K == NULL || C2 == NULL) return SM9_ASK_MEMORY_ERR;
		LinkCharZzn12(C, BNLEN * 2, w, Z, (Zlen - strlen(IDB)));
		memcpy(Z + BNLEN * 14, IDB, strlen(IDB));
		SM3_KDF(Z, Zlen, klen, K);
		printf("\n*****************K=KDF(C1||w||IDB,klen):***********************\n");
		for (i = 0; i < klen; i++) printf("%02x", K[i]);
		//Step:6-2: calculate C2=M^K1,and test if K1==0?
		for (i = 0; i < mlen; i++)
		{
			if (K[i] == 0) j = j + 1;
			C2[i] = message[i] ^ K[i];
		}
		if (j == mlen) return SM9_ERR_K1_ZERO;
		printf("\n************************* C2=M^K1 :***************************\n");
		for (i = 0; i < C2_len; i++) printf("%02x", C2[i]);
		//Step7:calculate C3=MAC(K2,C2)
		SM9_Enc_MAC(K + mlen, k2_len, C2, mlen, C3);
		printf("\n********************** C3=MAC(K2,C2):*************************\n");
		for (i = 0; i < 32; i++) printf("%02x", C3[i]);
		memcpy(C + BNLEN * 2, C3, SM3_len / 8);
		memcpy(C + BNLEN * 2 + SM3_len / 8, C2, C2_len);
		free(Z); free(K); free(C2);
	}
	else
	{
		C2_len = (mlen / 16 + 1) * 16;
		*C_len = BNLEN * 2 + SM3_len / 8 + C2_len;
		//Step:6-1: calculate K=KDF(C1||w||IDB,klen)
		klen = k1_len + k2_len;
		Zlen = strlen(IDB) + BNLEN * 14;
		Z = (char *)malloc(sizeof(char)*(Zlen + 1));
		K = (char *)malloc(sizeof(char)*(klen + 1));
		C2 = (char *)malloc(sizeof(char)*(C2_len + 1));
		if (Z == NULL || K == NULL || C2 == NULL) return SM9_ASK_MEMORY_ERR;
		LinkCharZzn12(C, BNLEN * 2, w, Z, Zlen - strlen(IDB));
		memcpy(Z + BNLEN * 14, IDB, strlen(IDB));
		SM3_KDF(Z, Zlen, klen, K);
		printf("\n*****************K=KDF(C1||w||IDB,klen):***********************\n");
		for (i = 0; i < klen; i++) printf("%02x", K[i]);
		//Step:6-2: calculate C2=Enc(K1,M),and also test if K1==0?
		for (i = 0; i < k1_len; i++)
		{
			if (K[i] == 0) j = j + 1;
		}
		if (j == k1_len) return SM9_ERR_K1_ZERO;
		SM4_Block_Encrypt(K, message, mlen, C2, &C2_len);
		printf("\n*********************** C2=Enc(K1,M) :*************************\n");
		for (i = 0; i < C2_len; i++) printf("%02x", C2[i]);
		//Step7:calculate C3=MAC(K2,C2)
		SM9_Enc_MAC(K + k1_len, k2_len, C2, C2_len, C3);
		printf("\n********************** C3=MAC(K2,C2):*************************\n");
		for (i = 0; i < 32; i++) printf("%02x", C3[i]);
		memcpy(C + BNLEN * 2, C3, SM3_len / 8);
		memcpy(C + BNLEN * 2 + SM3_len / 8, C2, C2_len);
		free(Z); free(K); free(C2);
	}
	return 0;
}
/****************************************************************
Function: SM9_Decrypt
Description: SM9 Decryption algorithm
Calls: MIRACL functions,zzn12_init(),Test_Point(), ecap(),
member(),zzn12_ElementPrint(),LinkCharZzn12(),SM3_KDF(),
SM9_Enc_MAC(),SM4_Block_Decrypt(),bytes128_to_ecn2()
Called By: SM9_SelfCheck()
Input:
C //cipher C1||C3||C2
C_len //the byte length of C
deB //private key of user B
IDB //identification of userB
EncID //encryption identification,0:stream cipher 1:block cipher
k1_len //the byte length of K1 in block cipher algorithm
k2_len //the byte length of K2 in MAC algorithm
Output:
M //message
Mlen: //the length of message
Return:
0: success
1: asking for memory error
2: element is out of order q
3: R-ate calculation error
4: test if C1 is on G1
A: K1 equals 0
B: compare error of C3
Others:
****************************************************************/
int SM9_Decrypt(unsigned char C[], int C_len, unsigned char deB[], unsigned char *IDB, int EncID,
	int k1_len, int k2_len, unsigned char M[], int * Mlen)
{
	big x, y;
	epoint *C1;
	zzn12 w;
	ecn2 dEB;
	int mlen, klen, Zlen, i, number = 0;
	unsigned char *Z = NULL, *K = NULL, *K1 = NULL, u[SM3_len / 8];
	x = mirvar(0); y = mirvar(0);
	dEB.x.a = mirvar(0); dEB.x.b = mirvar(0); dEB.y.a = mirvar(0); dEB.y.b = mirvar(0);
	dEB.z.a = mirvar(0); dEB.z.b = mirvar(0); dEB.marker = MR_EPOINT_INFINITY;
	C1 = epoint_init(); zzn12_init(&w);
	bytes_to_big(BNLEN, C, x); bytes_to_big(BNLEN, C + BNLEN, y);
	bytes128_to_ecn2(deB, &dEB);
	//Step1:get C1,and test if C1 is on G1
	epoint_set(x, y, 1, C1);
	if (Test_Point(C1)) return SM9_C1_NOT_VALID_G1;
	//Step2:w = e(C1, deB)
	if (!ecap(dEB, C1, para_t, X, &w)) return SM9_MY_ECAP_12A_ERR;
	//test if a ZZn12 element is of order q
	if (!member(w, para_t, X)) return SM9_MEMBER_ERR;
	printf("\n*********************** w = e(C1, deB):****************************\n");
	zzn12_ElementPrint(w);
	//Step3:Calculate plaintext
	mlen = C_len - BNLEN * 2 - SM3_len / 8;
	if (EncID == 0)
	{
		//Step3-1:calculate K=KDF(C1||w||IDB,klen)
		klen = mlen + k2_len;
		Zlen = strlen(IDB) + BNLEN * 14;
		Z = (char *)malloc(sizeof(char)*(Zlen + 1));
		K = (char *)malloc(sizeof(char)*(klen + 1));
		if (Z == NULL || K == NULL) return SM9_ASK_MEMORY_ERR;
		LinkCharZzn12(C, BNLEN * 2, w, Z, Zlen - strlen(IDB));
		memcpy(Z + BNLEN * 14, IDB, strlen(IDB));
		SM3_KDF(Z, Zlen, klen, K);
		printf("\n*****************K=KDF(C1||w||IDB,klen):***********************\n");
		for (i = 0; i < klen; i++) printf("%02x", K[i]);
		//Step:3-2: calculate M=C2^K1,and test if K1==0?
		for (i = 0; i < mlen; i++)
		{
			if (K[i] == 0) number += 1;
			M[i] = C[i + C_len - mlen] ^ K[i];
		}
		if (number == mlen) return SM9_ERR_K1_ZERO;
		*Mlen = mlen;
		//Step4:calculate u=MAC(K2,C2)
		SM9_Enc_MAC(K + mlen, k2_len, &C[C_len - mlen], mlen, u);
		if (memcmp(u, &C[BNLEN * 2], SM3_len / 8)) return SM9_C3_MEMCMP_ERR;
		printf("\n****************************** M:******************************\n");
		for (i = 0; i < mlen; i++) printf("%02x", M[i]);
		free(Z); free(K);
	}
	else
	{
		//Step:3-1: calculate K=KDF(C1||w||IDB,klen)
		klen = k1_len + k2_len;
		Zlen = strlen(IDB) + BNLEN * 14;
		Z = (char *)malloc(sizeof(char)*(Zlen + 1));
		K = (char *)malloc(sizeof(char)*(klen + 1));
		K1 = (char *)malloc(sizeof(char)*(k1_len + 1));
		if (Z == NULL || K == NULL || K1 == NULL) return SM9_ASK_MEMORY_ERR;
		LinkCharZzn12(C, BNLEN * 2, w, Z, Zlen - strlen(IDB));
		memcpy(Z + BNLEN * 14, IDB, strlen(IDB));
		SM3_KDF(Z, Zlen, klen, K);
		printf("\n*****************K=KDF(C1||w||IDB,klen):***********************\n");
		for (i = 0; i < klen; i++) printf("%02x", K[i]);
		//Step:3-2: calculate M=dec(K1,C2),and test if K1==0?
		for (i = 0; i < k1_len; i++)
		{
			if (K[i] == 0) number += 1;
			K1[i] = K[i];
		}
		if (number == k1_len) return SM9_ERR_K1_ZERO;
		SM4_Block_Decrypt(K1, &C[C_len - mlen], mlen, M, Mlen);
		//Step4:calculate u=MAC(K2,C2)
		SM9_Enc_MAC(K + k1_len, k2_len, &C[C_len - mlen], mlen, u);
		if (memcmp(u, &C[BNLEN * 2], SM3_len / 8)) return SM9_C3_MEMCMP_ERR;
		free(Z); free(K); free(K1);
	}
	return 0;
}
/****************************************************************
Function: SM9_SelfCheck
Description: SM9 self check
Calls: MIRACL functions,SM9_Init(),SM9_GenerateEncryptKey(),
SM9_Encrypt,SM9_Decrypt
Called By:
Input:
Output:
Return: 0: self-check success
1: asking for memory error
2: element is out of order q
3: R-ate calculation error
4: test if C1 is on G1
5: base point P1 error
6: base point P2 error
7: Encryption public key generated error
8: Encryption private key generated error
9: encryption error
A: K1 equals 0
B: compare error of C3
C: decryption error
Others:
****************************************************************/
/****************************************************************
Function: SM9_GenerateSignKey
Description: Generate Signed key
Calls: MIRACL functions,SM9_H1,xgcd,ecn2_Bytes128_Print
Called By: SM9_SelfCheck
Input: hid:0x01
ID:identification
IDlen:the length of ID
ks:master private key used to generate signature public key and private key
Output: Ppub:signature public key
dSA: signature private key
Return: 0: success;
1: asking for memory error
Others:
****************************************************************/
int SM9_GenerateSignKey(unsigned char hid[], unsigned char *ID, int IDlen, big ks, unsigned char Ppubs[], unsigned char dsa[])
{
	big h1, t1, t2, rem, xdSA, ydSA, tmp;
	unsigned char *Z = NULL;
	int Zlen = IDlen + 1, buf;
	ecn2 Ppub;
	epoint *dSA;
	h1 = mirvar(0); t1 = mirvar(0);
	t2 = mirvar(0); rem = mirvar(0); tmp = mirvar(0);
	xdSA = mirvar(0); ydSA = mirvar(0);
	dSA = epoint_init();
	Ppub.x.a = mirvar(0); Ppub.x.b = mirvar(0); Ppub.y.a = mirvar(0); Ppub.y.b = mirvar(0);
	Ppub.z.a = mirvar(0); Ppub.z.b = mirvar(0); Ppub.marker = MR_EPOINT_INFINITY;
	Z = (char *)malloc(sizeof(char)*(Zlen + 1));
	memcpy(Z, ID, IDlen);
	memcpy(Z + IDlen, hid, 1);
	buf = SM9_H1(Z, Zlen, N, h1);
	if (buf != 0) return buf;
	add(h1, ks, t1);//t1=H1(IDA||hid,N)+ks
	xgcd(t1, N, t1, t1, t1);//t1=t1(-1)
	multiply(ks, t1, t2); divide(t2, N, rem);//t2=ks*t1(-1)
											 //dSA=[t2]P1
	ecurve_mult(t2, P1, dSA);
	//Ppub=[ks]P2
	ecn2_copy(&P2, &Ppub);
	ecn2_mul(ks, &Ppub);
	printf("\n*********************The signed key = (xdA, ydA)：*********************\n");
	epoint_get(dSA, xdSA, ydSA);
	cotnum(xdSA, stdout); cotnum(ydSA, stdout);
	printf("\n**********************PublicKey Ppubs=[ks]P2：*************************\n");
	ecn2_Bytes128_Print(Ppub);
	epoint_get(dSA, xdSA, ydSA);
	big_to_bytes(BNLEN, xdSA, dsa, 1);
	big_to_bytes(BNLEN, ydSA, dsa + BNLEN, 1);
	redc(Ppub.x.b, tmp); big_to_bytes(BNLEN, tmp, Ppubs, 1);
	redc(Ppub.x.a, tmp); big_to_bytes(BNLEN, tmp, Ppubs + BNLEN, 1);
	redc(Ppub.y.b, tmp); big_to_bytes(BNLEN, tmp, Ppubs + BNLEN * 2, 1);
	redc(Ppub.y.a, tmp); big_to_bytes(BNLEN, tmp, Ppubs + BNLEN * 3, 1);
	free(Z);
	return 0;
}
/****************************************************************
Function: SM9_Sign
Description: SM9 signature algorithm
Calls: MIRACL functions,zzn12_init(),ecap(),member(),zzn12_ElementPrint(),
zzn12_pow(),LinkCharZzn12(),SM9_H2()
Called By: SM9_SelfCheck()
Input:
hid:0x01
IDA //identification of userA
message //the message to be signed
len //the length of message
rand //a random number K lies in [1,N-1]
dSA //signature private key
Ppubs //signature public key
Output: H,S //signature result
Return: 0: success
1: asking for memory error
4: element is out of order q
5: R-ate calculation error
9: parameter L error
Others:
****************************************************************/
int SM9_Sign(unsigned char hid[], unsigned char *IDA, unsigned char *message, int len, unsigned char rand[],
	unsigned char dsa[], unsigned char Ppub[], unsigned char H[], unsigned char S[])
{
	big h1, r, h, l, xdSA, ydSA;
	big xS, yS, tmp, zero;
	zzn12 g, w;
	epoint *s, *dSA;
	ecn2 Ppubs;
	int Zlen, buf;
	unsigned char *Z = NULL;
	//initiate
	h1 = mirvar(0); r = mirvar(0); h = mirvar(0); l = mirvar(0);
	tmp = mirvar(0); zero = mirvar(0);
	xS = mirvar(0); yS = mirvar(0);
	xdSA = mirvar(0); ydSA = mirvar(0);
	s = epoint_init(); dSA = epoint_init();
	Ppubs.x.a = mirvar(0);
	Ppubs.x.b = mirvar(0);
	Ppubs.y.a = mirvar(0);
	Ppubs.y.b = mirvar(0);
	Ppubs.z.a = mirvar(0);
	Ppubs.z.b = mirvar(0);
	Ppubs.marker = MR_EPOINT_INFINITY;
	zzn12_init(&g); zzn12_init(&w);
	bytes_to_big(BNLEN, rand, r);
	bytes_to_big(BNLEN, dsa, xdSA);
	bytes_to_big(BNLEN, dsa + BNLEN, ydSA);
	epoint_set(xdSA, ydSA, 0, dSA);
	bytes128_to_ecn2(Ppub, &Ppubs);
	//Step1:g = e(P1, Ppub-s)
	if (!ecap(Ppubs, P1, para_t, X, &g))
		return SM9_MY_ECAP_12A_ERR;
	//test if a ZZn12 element is of order q
	if (!member(g, para_t, X))
		return SM9_MEMBER_ERR;
	printf("\n***********************g=e(P1,Ppubs):****************************\n");
	zzn12_ElementPrint(g);
	//Step2:calculate w=g(r)
	printf("\n***********************randnum r:********************************\n");
	cotnum(r, stdout);
	w = zzn12_pow(g, r);
	printf("\n***************************w=gr:**********************************\n");
	zzn12_ElementPrint(w);
	//Step3:calculate h=H2(M||w,N)
	Zlen = len + 32 * 12;
	Z = (char *)malloc(sizeof(char)*(Zlen + 1));
	if (Z == NULL)
		return SM9_ASK_MEMORY_ERR;
	LinkCharZzn12(message, len, w, Z, Zlen);
	buf = SM9_H2(Z, Zlen, N, h);
	if (buf != 0)
		return buf;
	printf("\n****************************h:*************************************\n");
	cotnum(h, stdout);
	//Step4:l=(r-h)mod N
	subtract(r, h, l);
	divide(l, N, tmp);
	while (mr_compare(l, zero) < 0)
		add(l, N, l);
	if (mr_compare(l, zero) == 0)
		return SM9_L_error;
	printf("\n**************************l=(r-h)mod N:****************************\n");
	cotnum(l, stdout);
	//Step5:S=[l]dSA=(xS,yS)
	ecurve_mult(l, dSA, s);
	epoint_get(s, xS, yS);
	printf("\n**************************S=[l]dSA=(xS,yS):*************************\n");
	cotnum(xS, stdout); cotnum(yS, stdout);
	big_to_bytes(32, h, H, 1);
	big_to_bytes(32, xS, S, 1);
	big_to_bytes(32, yS, S + 32, 1);
	free(Z);
	return 0;
}
/****************************************************************
Function: SM9_Verify
Description: SM9 signature verification algorithm
Calls: MIRACL functions,zzn12_init(),Test_Range(),Test_Point(),
ecap(),member(),zzn12_ElementPrint(),SM9_H1(),SM9_H2()
Called By: SM9_SelfCheck()
Input:
H,S //signature result used to be verified
hid //identification
IDA //identification of userA
message //the message to be signed
len //the length of message
Ppubs //signature public key
Output: NULL
Return: 0: success
1: asking for memory error
2: H is not in the range[1,N-1]
6: S is not on the SM9 curve
4: element is out of order q
5: R-ate calculation error
3: h2!=h,comparison error
Others:
****************************************************************/
int SM9_Verify(unsigned char H[], unsigned char S[], unsigned char hid[], unsigned char *IDA, unsigned char *message, int len,
	unsigned char Ppub[])
{
	big h, xS, yS, h1, h2;
	epoint *S1;
	zzn12 g, t, u, w;
	ecn2 P, Ppubs;
	int Zlen1, Zlen2, buf;
	unsigned char * Z1 = NULL, *Z2 = NULL;
	h = mirvar(0);
	h1 = mirvar(0);
	h2 = mirvar(0);
	xS = mirvar(0);
	yS = mirvar(0);
	P.x.a = mirvar(0);
	P.x.b = mirvar(0);
	P.y.a = mirvar(0);
	P.y.b = mirvar(0);
	P.z.a = mirvar(0);
	P.z.b = mirvar(0);
	P.marker = MR_EPOINT_INFINITY;
	Ppubs.x.a = mirvar(0);
	Ppubs.x.b = mirvar(0);
	Ppubs.y.a = mirvar(0);
	Ppubs.y.b = mirvar(0);
	Ppubs.z.a = mirvar(0);
	Ppubs.z.b = mirvar(0);
	Ppubs.marker = MR_EPOINT_INFINITY;
	S1 = epoint_init();
	zzn12_init(&g), zzn12_init(&t);
	zzn12_init(&u); zzn12_init(&w);
	bytes_to_big(BNLEN, H, h);
	bytes_to_big(BNLEN, S, xS);
	bytes_to_big(BNLEN, S + BNLEN, yS);
	bytes128_to_ecn2(Ppub, &Ppubs);
	//Step 1:test if h in the rangge [1,N-1]
	if (Test_Range(h))
		return SM9_H_OUTRANGE;
	//Step 2:test if S is on G1
	epoint_set(xS, yS, 0, S1);
	if (Test_Point(S1))
		return SM9_S_NOT_VALID_G1;
	//Step3:g = e(P1, Ppub-s)
	if (!ecap(Ppubs, P1, para_t, X, &g))
		return SM9_MY_ECAP_12A_ERR;
	//test if a ZZn12 element is of order q
	if (!member(g, para_t, X))
		return SM9_MEMBER_ERR;
	printf("\n***********************g=e(P1,Ppubs):****************************\n");
	zzn12_ElementPrint(g);
	//Step4:calculate t=g(h)
	t = zzn12_pow(g, h);
	printf("\n***************************w=gh:**********************************\n");
	zzn12_ElementPrint(t);
	//Step5:calculate h1=H1(IDA||hid,N)
	Zlen1 = strlen(IDA) + 1;
	Z1 = (char *)malloc(sizeof(char)*(Zlen1 + 1));
	if (Z1 == NULL) return SM9_ASK_MEMORY_ERR;
	memcpy(Z1, IDA, strlen(IDA));
	memcpy(Z1 + strlen(IDA), hid, 1);
	buf = SM9_H1(Z1, Zlen1, N, h1);
	if (buf != 0) return buf;
	printf("\n****************************h1:**********************************\n");
	cotnum(h1, stdout);
	//Step6:P=[h1]P2+Ppubs
	ecn2_copy(&P2, &P);
	ecn2_mul(h1, &P);
	ecn2_add(&Ppubs, &P);
	//Step7:u=e(S1,P)
	if (!ecap(P, S1, para_t, X, &u)) return SM9_MY_ECAP_12A_ERR;
	//test if a ZZn12 element is of order q
	if (!member(u, para_t, X)) return SM9_MEMBER_ERR;
	printf("\n************************** u=e(S1,P):*****************************\n");
	zzn12_ElementPrint(u);
	//Step8:w=u*t
	zzn12_mul(u, t, &w);
	printf("\n************************* w=u*t: **********************************\n");
	zzn12_ElementPrint(w);
	//Step9:h2=H2(M||w,N)
	Zlen2 = len + 32 * 12;
	Z2 = (char *)malloc(sizeof(char)*(Zlen2 + 1));
	if (Z2 == NULL)
		return SM9_ASK_MEMORY_ERR;
	LinkCharZzn12(message, len, w, Z2, Zlen2);
	buf = SM9_H2(Z2, Zlen2, N, h2);
	if (buf != 0) return buf;
	printf("\n**************************** h2:***********************************\n");
	cotnum(h2, stdout);
	free(Z1);
	free(Z2);
	if (mr_compare(h2, h) != 0)
		return SM9_DATA_MEMCMP_ERR;
	return 0;
}
int main(int argc,char *argv[])
{
	//the master private key 三个都有引用
	unsigned char KE[32] = { 0x00,0x01,0xED,0xEE,0x37,0x78,0xF4,0x41,0xF8,0xDE,0xA3,0xD9,0xFA,0x0A,0xCC,0x4E,
	0x07,0xEE,0x36,0xC9,0x3F,0x9A,0x08,0x61,0x8A,0xF4,0xAD,0x85,0xCE,0xDE,0x1C,0x22 };
	unsigned char dA[32] = { 0x00,0x01,0x30,0xE7,0x84,0x59,0xD7,0x85,0x45,0xCB,0x54,0xC5,0x87,0xE0,0x2C,0xF4,
	0x80,0xCE,0x0B,0x66,0x34,0x0F,0x31,0x9F,0x34,0x8A,0x1D,0x5B,0x1F,0x2D,0xC5,0xF4 };
	unsigned char rand[32] = { 0x00,0x00,0xAA,0xC0,0x54,0x17,0x79,0xC8,0xFC,0x45,0xE3,0xE2,0xCB,0x25,0xC1,0x2B,
	0x5D,0x25,0x76,0xB2,0x12,0x9A,0xE8,0xBB,0x5E,0xE2,0xCB,0xE5,0xEC,0x9E,0x78,0x5C };
	//standard datas没有引用
	
	unsigned char h[32], S[64];										// Signature
	unsigned char h_t[32], S_t[64];
	unsigned char sign[2000]="AT";											//完整的签名，由h和S连接得到
	unsigned char std_message_t[1904];			//
	unsigned char hid[] = { 0x03 };									//
	unsigned char hid_S[] = { 0x01 };
	unsigned char *IDA = "Alice";									//用户1
	unsigned char *IDB = "Bob";										//用户2
	unsigned char Ppub_B[64], deB_B[128];								//Ppub是公钥，deB是私钥
	unsigned char Ppub_A_S[128], dSA[64];								//用户A的签名密钥
	unsigned char message[2000], C[2000];
	int M_len;//M_len the length of message
	int C_len;//C_len the length of C//C_len the length of signature
	int k1_len = 16, k2_len = 32;
	int EncID = 0;//0,stream //1 block
	int tmp, i;
	big ke,ks;
	int S_M_len = strlen(argv[1]);//The length of std_message
	tmp = SM9_Init();
	if (tmp != 0) return tmp;
	ke = mirvar(0);
	bytes_to_big(32, KE, ke);
	ks = mirvar(0);
	bytes_to_big(32, dA, ks);
	printf("\n*********************** SM9 key Generation ***************************\n");
	printf("\n*********************** The key of User B ***************************\n");
	tmp = SM9_GenerateEncryptKey(hid, IDB, strlen(IDB), ke, Ppub_B, deB_B);
	//if(memcmp(Ppub,std_Ppub,64)!=0)
	//return SM9_GEPUB_ERR;
	//if(memcmp(deB,std_deB,128)!=0)
	//return SM9_GEPRI_ERR;
	printf("\n*********************** The sign key of User A ***************************\n");
	tmp = SM9_GenerateSignKey(hid_S, IDA, strlen(IDA), ks, Ppub_A_S, dSA);
	if (tmp != 0)
		return tmp;
	/*if (memcmp(Ppub, std_Ppub, 128) != 0)
	return SM9_GEPUB_ERR;
	if (memcmp(dSA, std_dSA, 64) != 0)
	return SM9_GEPRI_ERR;*/
	printf("\n********************** SM9 signature algorithm***************************\n");
	tmp = SM9_Sign(hid_S, IDA, argv[1], S_M_len, rand, dSA, Ppub_A_S, h, S);
	if (tmp != 0) return tmp;
	/*if (memcmp(h, std_h, 32) != 0)
	return SM9_SIGN_ERR;
	if (memcmp(S, std_S, 64) != 0)
	return SM9_SIGN_ERR;*/
	//strcpy(sign, h);
	my_char_cat(sign, h, sizeof(h),0);
	my_char_cat(sign, S, sizeof(S), strlen(sign));
	strcat_s(sign, sizeof(sign), argv[1]);
	printf("\n*********************** SM9 encrypt algorithm **************************\n");
	tmp = SM9_Encrypt(hid, IDB, sign, strlen(sign), rand, EncID, k1_len, k2_len, Ppub_B, C, &C_len);
	if (tmp != 0) return tmp;
	printf("\n******************************Cipher:************************************\n");
	for (i = 0; i < C_len; i++) printf("%02x", C[i]);
	//if(EncID==0) tmp=memcmp(C,std_C_stream,C_len);else tmp=memcmp(C,std_C_cipher,C_len);
	//if(tmp) return SM9_ENCRYPT_ERR;
	printf("\n********************** SM9 Decrypt algorithm **************************\n");
	tmp = SM9_Decrypt(C, C_len, deB_B, IDB, EncID, k1_len, k2_len, message, &M_len);
	printf("\n**************************** Message:***********************************\n");

	for (i = 0; i < M_len; i++)
		printf("%02x", message[i]);

	if (tmp != 0) return tmp;
	//if(memcmp(message,argv[1],M_len)!=0)
	//return SM9_DECRYPT_ERR;
	strncpy(h_t, message, 32);
	strncpy(S_t, message + 32, 64);
	strncpy(std_message_t, message + 96, M_len - 96);
	if (!strcmp(h_t,h)||!strcmp(S_t,S)) {
		return SM9_SIGN_ERR;
	}
	if (!strcmp(std_message_t, argv[1])) {
		return SM9_ENCRYPT_ERR;
	}
	printf("\n******************* SM9 verification algorithm *************************\n");
	tmp = SM9_Verify(h_t, S_t, hid_S, IDA, std_message_t, sizeof(std_message_t), Ppub_A_S);
}
