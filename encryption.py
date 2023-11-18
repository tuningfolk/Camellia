MASK8 =  0xff
# MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
# MASK128 = 0xffffffffffffffffffffffffffffffff

#64 bit constants
Sigma1 = 0xA09E667F3BCC908B
Sigma2 = 0xB67AE8584CAA73B2
Sigma3 = 0xC6EF372FE94F82BE
Sigma4 = 0x54FF53A5F1D36F1C
Sigma5 = 0x10E527FADE682D1D
Sigma6 = 0xB05688C2B3E6C1FD
Sigma = [Sigma1, Sigma2, Sigma3, Sigma4, Sigma5, Sigma6]
for s in Sigma:
    print(len(bin(s))-2)

def encrypt(K: int, data: str):
    
    # Key scheduling
    #     The aim of key schedule is to prevent key-based attacks such as:
    #     ~related-key attack
    #     ~slide attack, rotational attack
    #     ~whitening(pre and post)
    # Sigmas are used as "keys" in the F-function
    
    KL = K
    KR = 0

    D1 = (KL ^ KR) >> 64
    D2 = (KL ^ KR) & MASK64
    D2 = D2 ^ F(D1, Sigma1)
    D1 = D1 ^ F(D2, Sigma2)
    D1 = D1 ^ (KL >> 64)
    D2 = D2 ^ (KL & MASK64)
    D2 = D2 ^ F(D1, Sigma3)
    D1 = D1 ^ F(D2, Sigma4)
    KA = (D1 << 64) | D2
    D1 = (KA ^ KR) >> 64
    D2 = (KA ^ KR) & MASK64
    D2 = D2 ^ F(D1, Sigma5)
    D1 = D1 ^ F(D2, Sigma6)

    return D1

def F(F_IN: int,KE: int ):
    '''
    F_IN: 64-bit input data
    KE: 64-bit subkey

    Returns F_OUT: 64-bit data
    '''
    
    #8-bit variables: t1,t2,t3,t4,t5,t6,t7,t8
    #8-bit variables: y1,y2,y3,y4,y5,y6,y7,y8
    x = F_IN ^ KE 
    t1 = x>>56
    t2 = (x >> 48) & MASK8
    t3 = (x >> 40) & MASK8
    t4 = (x >> 32) & MASK8
    t5 = (x >> 24) & MASK8
    t6 = (x >> 16) & MASK8
    t7 = (x >>  8) & MASK8
    t8 =  x        & MASK8    
    y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
    y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
    y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
    y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
    y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
    y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
    y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
    F_OUT = (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) | (y5 << 24) | (y6 << 16) | (y7 <<  8) | y8
    return F_OUT