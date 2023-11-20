NUM_OF_BITS=128
MASK8 =  0xff
MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
MASK128 = 0xffffffffffffffffffffffffffffffff

#64 bit constants
Sigma1 = 0xA09E667F3BCC908B # 64 bits
Sigma2 = 0xB67AE8584CAA73B2 # 64 bits
Sigma3 = 0xC6EF372FE94F82BE # 64 bits
Sigma4 = 0x54FF53A5F1D36F1C # 63 bits
Sigma5 = 0x10E527FADE682D1D # 61 bits
Sigma6 = 0xB05688C2B3E6C1FD # 64 bits


#SECRET KEY (128 bits)
K = 0xf54cfbf8329ef7564b1f9d85adf0f132

def sbox_to_list():
    str = '''
    112 130  44 236 179  39 192 229 228 133  87  53 234  12 174  65
    35 239 107 147  69  25 165  33 237  14  79  78  29 101 146 189
    134 184 175 143 124 235  31 206  62  48 220  95  94 197  11  26
    166 225  57 202 213  71  93  61 217   1  90 214  81  86 108  77
    139  13 154 102 251 204 176  45 116  18  43  32 240 177 132 153
    223  76 203 194  52 126 118   5 109 183 169  49 209  23   4 215
    20  88  58  97 222  27  17  28  50  15 156  22  83  24 242  34
    254  68 207 178 195 181 122 145  36   8 232 168  96 252 105  80
    170 208 160 125 161 137  98 151  84  91  30 149 224 255 100 210
    16 196   0  72 163 247 117 219 138   3 230 218   9  63 221 148
    135  92 131   2 205  74 144  51 115 103 246 243 157 127 191 226
    82 155 216  38 200  55 198  59 129 150 111  75  19 190  99  46
    233 121 167 140 159 110 188 142  41 245 249 182  47 253 180  89
    120 152   6 106 231  70 113 186 212  37 171  66 136 162 141 250
    114   7 185  85 248 238 172  10  54  73  42 104  60  56 241 164
    64  40 211 123 187 201  67 193  21 227 173 244 119 199 128 158'''


    strlist = str.split(' ')
    strlist = [s.split('\n') for s in strlist]
    strlist = [int(num) for s in strlist for num in s if num!='']
    return strlist

def left_rotate(n, d,bits):
    if bits == 8: mask = MASK8
    elif bits == 32: mask = MASK32
    elif bits == 64: mask = MASK64
    elif bits == 128: mask = MASK128
    else:
        print("Unsupported number of bits, create MASK value for "+str(bits)+" bits!")
        exit(1)
        
    return ((n<<d)|(n>>(bits-d)))&mask

def block_decryption(K: int, C: str):
    '''
    Inputs:
    K: 128 bits
    C: Plaintext

    Output:
    P: Plaintext
    '''
    # Key scheduling Part



    #     The aim of key schedule is to prevent key-based attacks such as:
    #     ~related-key attack
    #     ~slide attack, rotational attack
    #     ~whitening(pre and post)

    # Sigmas are used as "keys" in the F-function
    
    #128 bits
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
    
    bits = 128 #size in bits
    kw1 = (left_rotate(KL, 0, bits)) >> 64
    kw2 = left_rotate(KL, 0, bits) & MASK64
    k1  = left_rotate(KA, 0, bits) >> 64
    k2  = left_rotate(KA, 0, bits) & MASK64
    k3  = left_rotate(KL, 15, bits) >> 64
    k4  = left_rotate(KL, 15, bits) & MASK64
    k5  = left_rotate(KA, 15, bits) >> 64
    k6  = left_rotate(KA, 15, bits) & MASK64
    ke1 = left_rotate(KA, 30, bits) >> 64
    ke2 = left_rotate(KA, 15, bits) & MASK64
    k7  = left_rotate(KL, 45, bits) >> 64
    k8  = left_rotate(KL, 45, bits) & MASK64
    k9  = left_rotate(KA, 45, bits) >> 64
    k10 = left_rotate(KL, 60, bits) & MASK64
    k11 = left_rotate(KA, 60, bits) >> 64
    k12 = left_rotate(KA, 60, bits) & MASK64
    ke3 = left_rotate(KL, 77, bits) >> 64
    ke4 = left_rotate(KL, 77, bits) & MASK64
    k13 = left_rotate(KL, 94, bits) >> 64
    k14 = left_rotate(KL, 94, bits) & MASK64
    k15 = left_rotate(KA, 94, bits) >> 64
    k16 = left_rotate(KA, 94, bits) & MASK64
    k17 = left_rotate(KL, 111, bits) >> 64
    k18 = left_rotate(KL, 111, bits) & MASK64
    kw3 = left_rotate(KA, 111, bits) >> 64
    kw4 = left_rotate(KA, 111, bits) & MASK64

    D1 = C>>64
    D2 = C&MASK64
    
    D1 = D1 ^ kw3          # Prewhitening
    D2 = D2 ^ kw4
    D2 = D2 ^ F(D1, k18)    # Round 1
    D1 = D1 ^ F(D2, k17)    # Round 2
    D2 = D2 ^ F(D1, k16)    # Round 3
    D1 = D1 ^ F(D2, k15)    # Round 4
    D2 = D2 ^ F(D1, k14)    # Round 5
    D1 = D1 ^ F(D2, k13)    # Round 6
    D1 = FL   (D1, ke4)    # FL
    D2 = FLINV(D2, ke3)    # FLINV
    D2 = D2 ^ F(D1, k12)    # Round 7
    D1 = D1 ^ F(D2, k11)    # Round 8
    D2 = D2 ^ F(D1, k10)    # Round 9
    D1 = D1 ^ F(D2, k9)   # Round 10
    D2 = D2 ^ F(D1, k8)   # Round 11
    D1 = D1 ^ F(D2, k7)   # Round 12
    D1 = FL   (D1, ke2)    # FL
    D2 = FLINV(D2, ke1)    # FLINV
    D2 = D2 ^ F(D1, k6)   # Round 13
    D1 = D1 ^ F(D2, k5)   # Round 14
    D2 = D2 ^ F(D1, k4)   # Round 15
    D1 = D1 ^ F(D2, k3)   # Round 16
    D2 = D2 ^ F(D1, k2)   # Round 17
    D1 = D1 ^ F(D2, k1)   # Round 18
    D2 = D2 ^ kw1          # Postwhitening
    D1 = D1 ^ kw2

    P = (D2 << 64) | D1 #128 bit cipher text

    return P


def F(F_IN: int, KE: int):
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
    t1 = SBOX1[t1]
    t2 = SBOX2[t2]
    t3 = SBOX3[t3]
    
    t4 = SBOX1[left_rotate(t4, 1, 8)] #SBOX4
    
    t5 = SBOX2[t5]
    t6 = SBOX3[t6]
    t7 = SBOX1[left_rotate(t7, 1, 8)] #SBOX4
    t8 = SBOX1[t8]
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

def FL(FL_IN: int, KE: int):
    '''
    Inputs:
    FL: 64-bit input data 
    KE: 64-bit subkey

    Returns:
    FL_OUT: 64-bit data
    '''

    #x1, x2 as 32-bit unsigned integer
    #k1, k2 as 32-bit unsigned integer
    x1 = FL_IN >> 32
    x2 = FL_IN & MASK32
    k1 = KE >> 32
    k2 = KE & MASK32
    x2 = x2 ^ left_rotate((x1 & k1), 1, 32)
    x1 = x1 ^ (x2 | k2)
    FL_OUT = (x1 << 32) | x2

    return FL_OUT

def FLINV(FLINV_IN, KE):
    '''
    Inverse of FL-function

    Inputs:
        FLINV_IN: 64-bit
        KE: 64-bit subkey

    Outputs:
        FLINV_OUT: 64-bit
    '''
  
    # y1, y2 as 32-bit unsigned integer
    # k1, k2 as 32-bit unsigned integer
    y1 = FLINV_IN >> 32
    y2 = FLINV_IN & MASK32
    k1 = KE >> 32
    k2 = KE & MASK32
    y1 = y1 ^ (y2 | k2)
    y2 = y2 ^ left_rotate(y1 & k1, 1, 32)
    FLINV_OUT = (y1 << 32) | y2

    return FLINV_OUT

def decryption(K, C):
    '''
    Decrypts each block
    Each block is of size 129 bits, with the 129th bit 
    being 1 as the starting bit of the block.


    Inputs:
    K: Any number of bits
    C: Plaintext

    Output:
    P: Plaintext
    '''

    #Ciphertext is converted to binary string
    C = bin(C)[2:]
    P = ""
    #making sure ciphertext consists of blocks of size 129
    if len(C)%129!=0:
        print("Cipher text doesn't consist of blocks of size 129. Please check again.")
        exit(1)
    #Splitting into blocks
    r = len(C)-1
    l = r-128
    while r>=0:
        C_block = C[l+1:r+1] #starting bit is discarded
        P_block = block_decryption(K,int(C_block, 2))
        binary_P_block = str(bin(P_block)[2:])
        P_block = "0"*(NUM_OF_BITS-len(binary_P_block)) + binary_P_block
        P = P_block + P
        
        r = l-1
        l = r-128
    return int(P,2)

def int_to_text(P_numeric):
    P_numeric = str(P_numeric) #converted to string

    if len(P_numeric)%3!=1:
        
        print("Invalid ciphertext. Please check again")
        exit(1)
    
    result = ""
    #starting int "1" is discarded
    for i in range(1,len(P_numeric)-2,3):
        
        result += chr(int(P_numeric[i:i+3]))
    return result


SBOX1 = sbox_to_list()
SBOX2 = [left_rotate(num,1,8) for num in SBOX1]
SBOX3 = [left_rotate(num,7,8) for num in SBOX1]
C = int(input("Please enter the ciphertext: "))
P_numeric = decryption(K, C)

P = int_to_text(P_numeric)

print("The plaintext is:",P)