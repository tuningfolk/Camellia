#include<stdio.h>
#include<inttypes.h>

const MASK8 =  0xff;
const MASK32 = 0xffffffff;
const MASK64 = 0xffffffffffffffff;
const MASK128 = 0xffffffffffffffffffffffffffffffff;

const Sigma1 = 0xA09E667F3BCC908B;
const Sigma2 = 0xB67AE8584CAA73B2;
const Sigma3 = 0xC6EF372FE94F82BE;
const Sigma4 = 0x54FF53A5F1D36F1C;
const Sigma5 = 0x10E527FADE682D1D;
const Sigma6 = 0xB05688C2B3E6C1FD;




int encrypt(int K, char* data){
    /*
    Key scheduling
        The aim of key schedule is to prevent key-based attacks such as:
        ~related-key attack
        ~slide attack, rotational attack
        ~whitening(pre and post)
    Sigmas are used as "keys" in the F-function
    */
    int KL = K;
    int KR = 0;

    int D1 = (KL ^ KR) >> 64;
    int D2 = (KL ^ KR) & MASK64;
    D2 = D2 ^ F(D1, Sigma1);
    D1 = D1 ^ F(D2, Sigma2);
    D1 = D1 ^ (KL >> 64);
    D2 = D2 ^ (KL & MASK64);
    D2 = D2 ^ F(D1, Sigma3);
    D1 = D1 ^ F(D2, Sigma4);
    int KA = (D1 << 64) | D2;
    D1 = (KA ^ KR) >> 64;
    D2 = (KA ^ KR) & MASK64;
    D2 = D2 ^ F(D1, Sigma5);
    D1 = D1 ^ F(D2, Sigma6);

    return D1;
}

int F(int F_IN,int KE){
    uint64_t x;
    uint8_t t1,t2,t3,t4,t5,t6,t7,t8;
    uint8_t y1,y2,y3,y4,y5,y6,y7,y8;
    x = F_IN ^ KE;
    t1 = x>>56;
    t2 = (x >> 48) & MASK8;
    t3 = (x >> 40) & MASK8;
    t4 = (x >> 32) & MASK8;
    t5 = (x >> 24) & MASK8;
    t6 = (x >> 16) & MASK8;
    t7 = (x >>  8) & MASK8;
    t8 =  x        & MASK8;    
    

}