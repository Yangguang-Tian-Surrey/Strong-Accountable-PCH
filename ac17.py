from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False
#debug=True

Tlen = 210


class AC17CPABE(ABEnc):
    def __init__(self, group_obj, assump_size, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.assump_size = assump_size  # size of linear assumption, at least 2
        self.util = MSP(self.group, verbose)

    def get_group_obj(self):
        return self.group

    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')

        # generate two instances of the k-linear assumption
        A = []
        B = []



        for i in range(self.assump_size):
            A.append(self.group.random(ZR))
            B.append(self.group.random(ZR))  # note that A, B are vectors here

        # vector
        k = []
        for i in range(self.assump_size + 1):
            k.append(self.group.random(ZR))

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)
        h = self.group.random(G2)
        e_gh = pair(g, h)

        # chameleon hash key
        csk = self.group.random(ZR)
        cpk = g ** csk

        # blind factor bor bit-commitment
        z=self.group.random(ZR)
        Z=[] # Z_1, Z_2
        Z.append(g ** z)
        Z.append(h ** z)

        # Bit commitment
        BCSK=[]    # r_0, s_0
        BCPK=[]  # E, F, , V, W
        BCSK.append(self.group.random(ZR))
        BCSK.append(self.group.random(ZR))
        for i in range(self.assump_size):
            BCPK.append(g ** (1/A[i]))        # E=BCPK[0],  F=BCPK[1]
        BCPK.append(BCPK[0] ** BCSK[0])    # U     2
        BCPK.append(BCPK[1] ** BCSK[1])     # F      3
        BCPK.append(g ** (BCSK[0]+BCSK[1])) # W    4

        # now compute various parts of the public parameters

        # compute the [A]_2 term
        h_A = []                 #H_1, H_2--------------------------------------
        for i in range(self.assump_size):
            h_A.append(h ** A[i])
        h_A.append(h)

        # compute the e([k]_1, [A]_2) term
        g_k = []      # g^{{d_1}; g^{d_2}; g^{d_3}   -------------------------------
        for i in range(self.assump_size + 1):
            g_k.append(g ** k[i])

        e_gh_kA = []    # T_1, T_2 --------------------------------------
        for i in range(self.assump_size):
            e_gh_kA.append(e_gh ** ((k[i] * A[i] + z*k[self.assump_size])))

        # the public key
        pk = {'g': g, 'h': h,'h_A': h_A, 'e_gh_kA': e_gh_kA,'cpk':cpk,'BCPK':BCPK,'Z':Z}

        # the master secret key
        msk = { 'g_k': g_k, 'A': A, 'B': B,'csk':csk,'z':z,'BCSK':BCSK}

        return pk, msk

    def keygen(self, id, pk, msk, attr_list):
        """
        Generate a key for a list of attributes.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        # pick randomness
        r = []
        w=self.group.random(ZR)
        ss = self.group.random(ZR)
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            r.append(rand)
            sum += rand

        # compute the [Br]_2 term

        # first compute just Br as it will be used later too
        Br = []
        for i in range(self.assump_size):
            Br.append(msk['B'][i] * r[i])
        Br.append(sum * msk['z'])

        # now compute [Br]_2
        K_0 = []
        for i in range(self.assump_size + 1):
            K_0.append(pk['h'] ** Br[i])

        # compute [W_1 Br]_1, ...
        K = {}
        A = msk['A']
        g = pk['g']
        z = msk['z']
        csk = msk['csk']

        for attr in attr_list:
            key = []
            sigma_attr = self.group.random(ZR)
            for t in range(self.assump_size):
                prod = 1
                a_t = A[t]
                for l in range(self.assump_size + 1):
                    input_for_hash = attr + str(l) + str(t)
                    prod *= (self.group.hash(input_for_hash, G1) ** (Br[l]/a_t))
                prod *= (g ** (z*sigma_attr/a_t))           # mul z..............
                key.append(prod)
            key.append(g ** (-sigma_attr))
            K[attr] = key

        # compute [k + VBr]_1
        Kp = []
        g_k = msk['g_k']
        sigma = self.group.random(ZR)
        for t in range(self.assump_size):
            prod = g_k[t]
            a_t = A[t]
            for l in range(self.assump_size + 1):
                input_for_hash = '01' + str(l) + str(t)
                prod *= (self.group.hash(input_for_hash, G1) ** (Br[l] / a_t))
            prod *= (g ** (z*sigma / a_t))        # mul z..............
            Kp.append(prod)
        Kp.append(g_k[self.assump_size] * (g ** (-sigma)))


        # Compute K_1
        K_1=[]
        K_1.append(((pk['BCPK'][2] ** id)* (pk['BCPK'][0] ** w))** msk['z'])
        K_1.append(((pk['BCPK'][3] ** id) * (pk['BCPK'][1] ** ss)) ** msk['z'])
        K_1.append((pk['BCPK'][4] ** id) * (g ** (w+ss)))
        K_1.append((pk['BCPK'][4] ** id) * (g ** (w+ss)) * g ** id)

        K_2 = []
        K_2.append(w)
        K_2.append(ss)

        return {'attr_list': attr_list, 'K_0': K_0, 'K': K, 'Kp': Kp,'K_1':K_1,'K_2':K_2,'csk':csk}

    def encrypt(self, pk, msg, policy_str):
        """
        Encrypt a message msg under a policy string.
        """
        #m1=msg[0]
        #m2=msg[1]

        if debug:
            print('\nEncryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        s = []
        sum = 0
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            s.append(rand)
            sum += rand

        # compute the [As]_2 term
        C_0 = []
        h_A = pk['h_A']
        for i in range(self.assump_size):
            C_0.append(h_A[i] ** s[i])
        Z_2=pk['Z'][1]
        #C_0.append(h_A[self.assump_size] ** sum)
        C_0.append(Z_2 ** sum)

        C_0.append(h_A[0] ** s[1])
        C_0.append(h_A[1] ** s[0])
        # compute the [(V^T As||U^T_2 As||...) M^T_i + W^T_i As]_1 terms

        # pre-compute hashes
        hash_table = []
        for j in range(num_cols):
            x = []
            input_for_hash1 = '0' + str(j + 1)
            for l in range(self.assump_size + 1):
                y = []
                input_for_hash2 = input_for_hash1 + str(l)
                for t in range(self.assump_size):
                    input_for_hash3 = input_for_hash2 + str(t)
                    hashed_value = self.group.hash(input_for_hash3, G1)
                    y.append(hashed_value)
                    # if debug: print ('Hash of', i+2, ',', j2, ',', j1, 'is', hashed_value)
                x.append(y)
            hash_table.append(x)

        C = {}
        for attr, row in list(mono_span_prog.items()):
            ct = []
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
            for l in range(self.assump_size + 1):
                prod = 1
                cols = len(row)
                for t in range(self.assump_size):
                    input_for_hash = attr_stripped + str(l) + str(t)
                    prod1 = self.group.hash(input_for_hash, G1)
                    for j in range(cols):
                        # input_for_hash = '0' + str(j+1) + str(l) + str(t)
                        prod1 *= (hash_table[j][l][t] ** row[j])
                    prod *= (prod1 ** s[t])
                ct.append(prod)
            C[attr] = ct

        # compute the e(g, h)^(k^T As) . m term
        Cp = 1
        for i in range(self.assump_size):
            Cp = Cp * (pk['e_gh_kA'][i] ** s[i])

       # print("K0:", Cp)
        seed= str(Cp)
        seed = seed[:Tlen]
        #print("enc k:", seed,len(seed))
#generate two sub-keys
        K1=self.group.hash(seed+str(00),ZR)
        #K2=self.group.hash(seed+str(10),G2)

        Cpp = []
        Cpp.append(K1*msg)
       # Cpp.append(K2*m2)



        return {'policy': policy, 'C_0': C_0, 'C': C, 'Cp': Cpp}

    def decrypt(self, pk, ctxt, key):
        """
        Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('\nDecryption algorithm:\n')

        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prod1_GT = 1
        prod2_GT = 1

# Compute the bit-commitment................
        BC1_GT=  pair(ctxt['C_0'][0] * ctxt['C_0'][3],key['K_1'][0])
        BC1_GT=BC1_GT * pair(ctxt['C_0'][1] * ctxt['C_0'][4],key['K_1'][1])

        BC2_GT = pair(ctxt['C_0'][2],key['K_1'][2])

        for i in range(self.assump_size + 1):
            #print("i=",i)
            prod_H = 1
            prod_G = 1
            for node in nodes:
                attr = node.getAttributeAndIndex()
                attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
                # prod_H *= key['K'][attr_stripped][i] ** coeff[attr]
                # prod_G *= ctxt['C'][attr][i] ** coeff[attr]
                prod_H *= key['K'][attr_stripped][i]
                prod_G *= ctxt['C'][attr][i]
            prod1_GT *= pair(key['Kp'][i] * prod_H, ctxt['C_0'][i])
            prod2_GT *= pair(prod_G, key['K_0'][i])
        prod1_GT *= BC1_GT          # mul BC
        prod2_GT *= BC2_GT          # mul BC

        Cpp = ctxt['Cp']
        K = prod2_GT/prod1_GT

        seed = str(K)
        # le = len(seed)
        # # print("len:",le)
        # le = le / 2
        # le = int(le) - Tlen
        seed = seed[:Tlen]


        K1 = self.group.hash(seed + str(00), ZR)
        #K2 = self.group.hash(seed + str(10), G2)

        #print("dec k:", seed, len(seed))

        M = (Cpp[0]/K1)

        return M
