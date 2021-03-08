from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT,pair
from ac17 import AC17CPABE
from charm.toolbox.ABEnc import ABEnc
import string
import hashlib
import time


#variables

Test_Setup=True
Test_KeyGen = True
Test_Hash = True
Test_Adapt = True
Test_Judge =False

# keys
sig_params = {}
group = None


def Setup(N):
    pairing_group = PairingGroup('MNT224')

    # AC17 CP-ABE under DLIN (2-linear)
    cpabe = AC17CPABE(pairing_group, 2)

    # run the set up
    (pk, msk) = cpabe.setup()
    
    g = pk['g']
    h = pk['h']
    alpha = cpabe.group.random(ZR)
    beta = cpabe.group.random(ZR)
    g_beta = g ** beta
    h_1_alpha = h ** (1/alpha)
    h_beta_alpha = h ** (beta/alpha)
    beta_alpha = beta / alpha
    sig_params = {'g_beta':g_beta, 'h_1_alpha':h_1_alpha, 'h_beta_alpha':h_beta_alpha, 'beta_alpha':beta_alpha}

    attr_list = []
    i = 0
    while i < N:
        attr_list.append(str(i))
        i += 1

    return cpabe,pk,msk, pairing_group, attr_list, sig_params


def KeyGen(cpabe, id, pk, msk, attr_list):
    key = cpabe.keygen(id, pk, msk, attr_list)
    return key

def Hash(cpabe,pk,msg,policy_str,key,sig_params):
    h=pk['h']
    g = pk['g']
    group = cpabe.get_group_obj()

    r = cpabe.group.random(ZR)
    R = cpabe.group.random(ZR)
    g_ch = g ** R
    b_ch = g ** msg * g_ch ** r

    ctxt = cpabe.encrypt(pk, R, policy_str)

    # TODO step 3 signature
    sk = cpabe.group.random(ZR)
    esk = cpabe.group.random(ZR)
    ask = sk
    aesk = esk 
    c = sig_params['h_beta_alpha'] ** (ask+R)
    sha256 = hashlib.new('sha256')
    sha256.update(group.serialize(c))   
    hd = sha256.hexdigest() 
    seed = str(hd)

    sigma_prime = sig_params['g_beta'] ** ask * group.hash(seed, G1) ** aesk
    sigma_2prime = sig_params['h_1_alpha'] ** aesk

    vk = pair(g,sig_params['h_beta_alpha']) ** ask
    apk = h ** sk
    sigma = {'sigma_prime':sigma_prime, 'sigma_2prime':sigma_2prime}


    return msg, g_ch, r, b_ch, ctxt, c, vk, sigma, apk

def Verify(cpabe, pk, msg, g_ch, r, b_ch, ctxt, c, vk, sig_params, sigma):
    g = pk['g']
    b_prime = g ** msg * g_ch ** r
    group = cpabe.get_group_obj()

    sha256 = hashlib.new('sha256')
    sha256.update(group.serialize(c))
    hd = sha256.hexdigest() 
    seed = str(hd)
    pair1 = pair(sigma['sigma_prime'], sig_params['h_1_alpha'])
    pair2 = vk * pair(group.hash(seed, G1), sigma['sigma_2prime'])

    if (b_ch == b_prime and pair1 == pair2):
        return 0
    else:
        return 1


def Adapt(cpabe,pk, msg, g_ch, r, b_ch, ctxt, key, c, vk, sig_params, sigma, apk):
    g = pk['g']
    h = pk['h']
    group = cpabe.get_group_obj()
    msg_prime = 1034387

    if (Verify(cpabe, pk, msg, g_ch, r, b_ch, ctxt, c, vk, sig_params, sigma) != 0):
        return 1
    
    R_prime = cpabe.decrypt(pk, ctxt, key)
    r_prime = r + (msg - msg_prime) / R_prime

    sk_prime = cpabe.group.random(ZR)
    esk_prime = cpabe.group.random(ZR)
    ask_prime = sk_prime
    aesk_prime = esk_prime 
    c_prime = sig_params['h_beta_alpha'] ** (ask_prime+R_prime)
    sha256 = hashlib.new('sha256')
    sha256.update(group.serialize(c_prime))    
    hd = sha256.hexdigest() 
    seed = str(hd)

    sigma_prime = sig_params['g_beta'] ** ask_prime * group.hash(seed, G1) ** aesk_prime
    sigma_2prime = sig_params['h_1_alpha'] ** aesk_prime

    vk_prime = pair(g,sig_params['h_beta_alpha']) ** ask_prime
    apk_prime = h ** sk_prime
    sigma = {'sigma_prime':sigma_prime, 'sigma_2prime':sigma_2prime}
    
    return msg_prime, g_ch, r_prime, b_ch, ctxt, c_prime, vk_prime, sigma, apk_prime


def Judge(cpabe, id, key, pk, msk, apk, msg, g_ch, r, b_ch, ctxt, c, vk, sig_params, sigma, msg_prime, r_prime, c_prime, vk_prime, sigma_prime):
    h = pk['h']
    g = pk['g']
    rs = 0

    if (Verify(cpabe, pk, msg, g_ch, r, b_ch, ctxt, c, vk, sig_params, sigma) == 0 and Verify(cpabe, pk, msg_prime, g_ch, r_prime, b_ch, ctxt, c_prime, vk_prime, sig_params, sigma_prime) == 0):
        rs = 0
    else:
        rs = 1

    delta_sk = pair(pk['g'], c_prime / c)
    if (vk_prime == vk * delta_sk):
        rs = 0
    else:
        rs = 1

    Z_1 = pk['Z'][0]
    sk_1 = key['K_1'][0]
    sk_2 = key['K_1'][1]
    sk_3 = key['K_1'][2]
    sk_4 = key['K_1'][3]
    z = msk['z']
    a_1 = msk['A'][0]
    a_2 = msk['A'][1]


    Z_right = sk_4 ** z * sk_1 ** (-a_1) * sk_2 ** (-a_2)
    Z_left = Z_1 ** id

    if (Z_left != Z_right):
        rs = 1	# failed

    if (vk != pair(g,apk) ** sig_params['beta_alpha']):
        rs = 1	# failed

    return rs




def main():
    d = 10
    trial = 100
    Test_Setup = False
    Test_KeyGen = False
    Test_Hash = False
    Test_Adapt = False
    Test_Verify = False
    Test_Judge = True
    id = 1010
    msg = 1034342

    # instantiate a bilinear pairing map
    #pairing_group = PairingGroup('MNT224')
    
    # AC17 CP-ABE under DLIN (2-linear)
    #pchba = PCHBA(pairing_group, 2, 10)	# k = 10 (depth of the tree)

    # run the set up
    (cpabe,pk,msk, pairing_group, attr_list, sig_params) =Setup(d)

    if Test_Setup:
        print ('Testing Setup ...')
        k = 10
        f = open('result_setup.txt', 'w+')
        f.write("("+str(k)+",")
        T=0
        Temp=0
        start = 0
        end = 0
        for i in range(trial):
            start = time.time()
            (cpabe,pk,msk, pairing_group, attr_list, sig_params) =Setup(d)
            end = time.time()
            Temp=end - start
            T+=Temp
        T=T/trial
        f.write(str(T) + ")\n")
        f.close()

    # generate a key
    #attr_list = ['ONE', 'TWO', 'THREE']
    #sk_delta = pchba.keygen(sk, pk, msk, mpk, attr_list)
    key = KeyGen(cpabe, id, pk, msk,attr_list)

    if Test_KeyGen:
        print ('Testing KeyGen ...')
        d=10      # number of attributes
        NN = 100
        
        f = open('result_keygen.txt', 'w+')
        while d <= NN:
            print (d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(d):
                attr_list.append(str(i))
            for i in range(trial):
                start = time.time()
                key = KeyGen(cpabe, id, pk, msk,attr_list)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

   
    # generate a ciphertext
    policy_str=""
    for j in range(d):
        if j!=d-1:
            policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
        else:
            policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"

    (msg, g_ch, r, b_ch, ctxt, c, vk, sigma, apk) = Hash(cpabe,pk,msg,policy_str, key, sig_params)

    if Test_Hash:
        print ('Testing Hash ...')
        d=10      # number of attributes
        NN = 100
        f = open('result_hash.txt', 'w+')
        while d <= NN:
            print (d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key = KeyGen(cpabe, id, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            for i in range(trial):
                m = None
                start = time.time()
                (msg, g_ch, r, b_ch, ctxt, c, vk, sigma, apk) = Hash(cpabe,pk,msg,policy_str, key, sig_params)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    if (Verify(cpabe, pk, msg, g_ch, r, b_ch, ctxt, c, vk, sig_params, sigma) == 0):
        print ("Hash: Successful verification.")
    else:
        print ("Hash: Verification failed.")

    if Test_Verify:
        print ('Testing Verify ...')
        d=10      # number of attributes
        NN = 100
        f = open('result_verify.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key = KeyGen(cpabe, id, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            (msg, g_ch, r, b_ch, ctxt, c, vk, sigma, apk) = Hash(cpabe,pk,msg,policy_str, key, sig_params)
            
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                Verify(cpabe, pk, msg, g_ch, r, b_ch, ctxt, c, vk, sig_params, sigma)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()


    (msg_prime, g_ch, r_prime, b_ch, ctxt, c_prime, vk_prime, sigma_prime, apk_prime) = Adapt(cpabe,pk, msg, g_ch, r, b_ch, ctxt, key, c, vk, sig_params, sigma, apk)

    if Test_Adapt:
        print ('Testing Adapt ...')
        d=10      # number of attributes
        NN = 100
        f = open('result_adapt.txt', 'w+')
        while d <= NN:
            print (d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key = KeyGen(cpabe, id, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            (msg, g_ch, r, b_ch, ctxt, c, vk, sigma, apk) = Hash(cpabe,pk,msg,policy_str, key, sig_params)
            
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                (msg_prime, g_ch, r_prime, b_ch, ctxt, c_prime, vk_prime, sigma_prime, apk_prime) = Adapt(cpabe,pk, msg, g_ch, r, b_ch, ctxt, key, c, vk, sig_params, sigma, apk)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
    
    if (Verify(cpabe, pk, msg_prime, g_ch, r_prime, b_ch, ctxt, c_prime, vk_prime, sig_params, sigma_prime) == 0):
        print ("Adapt: Successful verification.")
    else:
        print ("Adapt: Verification failed.")

    if (Judge(cpabe, id, key, pk, msk, apk, msg, g_ch, r, b_ch, ctxt, c, vk, sig_params, sigma, msg_prime, r_prime, c_prime, vk_prime, sigma_prime) == 0):
        print ("Judge: Successful verification.")
    else:
        print ("Judge: Verification failed.")
    
    if Test_Judge:
        print ('Testing Judge ...')
        d=10      # number of attributes
        NN = 100
        f = open('result_judge.txt', 'w+')
        while d <= NN:
            print (d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            key = KeyGen(cpabe, id, pk, msk,attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            (msg, g_ch, r, b_ch, ctxt, c, vk, sigma, apk) = Hash(cpabe,pk,msg,policy_str, key, sig_params)
            m_prime = None 
            ID_i = None
            (msg_prime, g_ch, r_prime, b_ch, ctxt, c_prime, vk_prime, sigma_prime, apk_prime) = Adapt(cpabe,pk, msg, g_ch, r, b_ch, ctxt, key, c, vk, sig_params, sigma, apk)
            
            for i in range(trial):
                start = time.time()
                Judge(cpabe, id, key, pk, msk, apk, msg, g_ch, r, b_ch, ctxt, c, vk, sig_params, sigma, msg_prime, r_prime, c_prime, vk_prime, sigma_prime)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

'''
    NN = 100
    d=10
    trial=100
    id = 1010
    msg = 1034342

    #Setup benchmark
    (cpabe,pk,msk, pairing_group, attr_list, sig_params) =Setup(d)
    key = KeyGen(cpabe, id, pk, msk,attr_list)

    policy_str=""
    for j in range(d):
        if j!=d-1:
            policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
        else:
            policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"

    (msg, g_ch, r, b_ch, ctxt, c, vk, sigma, apk) = Hash(cpabe,pk,msg,policy_str, key, sig_params)
    Verify(cpabe, pk, msg, g_ch, r, b_ch, ctxt, c, vk, sig_params, sigma)
    (msg_prime, g_ch, r_prime, b_ch, ctxt, c_prime, vk_prime, sigma_prime, apk_prime) = Adapt(cpabe,pk, msg, g_ch, r, b_ch, ctxt, key, c, vk, sig_params, sigma, apk)
    Verify(cpabe, pk, msg_prime, g_ch, r_prime, b_ch, ctxt, c_prime, vk_prime, sig_params, sigma_prime)
    Judge(cpabe, id, key, pk, msk, apk, msg, g_ch, r, b_ch, ctxt, c, vk, sig_params, sigma, msg_prime, r_prime, c_prime, vk_prime, sigma_prime)
'''



if __name__ == "__main__":
    #debug = False
    debug = True
    main()
