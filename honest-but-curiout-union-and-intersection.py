
# coding: utf-8

# In[ ]:


from paillier import *


# In[ ]:


import math
import random
from random import shuffle
import sys
import gmpy2
from time import time
from Crypto.Util.number import getPrime
import numpy as np


# In[ ]:


# In[4]:


#UNION SET FOR HONEST BUT CURIOUS
def enc_function(s1):
    #using this function P1 can generate his encrypted polynomial
    p=np.poly1d(s1, True)
    enc_coef=[]
    for i in range(len(p),-1,-1):
        enc_coef.append(encrypt(pub,int(p.c[i])))
    return enc_coef


# In[5]:


def s2calcfun(s1,x,enc_coef):
    #P2 uses this function to evaluate a value from s2 in the encrypted polynomial
    p=np.poly1d(s1, True)
    mulfac=[]
    f1=1
    for i in range(0,len(enc_coef)):
        mulfac.append(multime(pub, enc_coef[i], f1))#multiply each coefficient with the proper x
        f1=f1*x
    #we created the list which has the values of the encrypted coef multiplied with each x
    #now we need to add everything together
    init=encrypt(pub,0)#value which everything will be added there
    for i in range(0,len(enc_coef)):
        init=addemup(pub,init,mulfac[i])
    return init


# In[6]:


#now p2 using the s2calcfun should generate the encrypted output for every element
#in the s2 and return it to p1
def gen_tuples(s2,enc_coef):
    en1=[]
    en2=[]
    r=random.getrandbits(64)
    for i in range(0,len(s2)):
        val=s2calcfun(s1,s2[i],enc_coef)
        en1.append(multime(pub, val, r*s2[i]))#multiply with the random value and a value from s2
        en2.append(multime(pub, val,r))       #multiply only with the random value
    c = list(zip(en1, en2))
    random.shuffle(c)
    en1, en2 = zip(*c)#shuffle and send the pairs
    return en1,en2


# In[7]:


def output(s1,en1,en2):
    output_values=s1 #P1 initially set the output to be s1
    for i in range(0,len(s2)):
        a=decrypt(priv,pub,en1[i])
        b=decrypt(priv,pub,en2[i])
        if(a!=0)and(b!=0):
            output_values.append(int(gmpy2.f_div(a,b)))
    return output_values


# In[8]:


priv, pub = generate_keypair(2048)#generate crypto scheme to work on
s1=[9,32,17,45,98,23,54,234,87] # P1 defines the his set s1
s2=[19,65,17,54,8,76,29,81,87,36,23]#P2 defines his set s2
def test_function():
    print "running test function for the union of the 2 sets (question 2)"
    alice=enc_function(s1)          #P1(alice) creates the encrypted coefficients of the polynomial
                                    #and grants access to it to P2 along with the pub value generated above
        
    en1,en2=gen_tuples(s2,alice)    #P2(bob) is now generating the tuples according to the 
                                    #Two-party HBC protocol for Set Union, and sends them to P1
    
    return output(s1,en1,en2)       #P1 returns the union of s1 and s2


# In[9]:


print test_function()


# In[10]:


#INTERSECTION SET FOR HONEST BUT CURIOUS
# In[11]:


def gen_tuples_q3(s1,s2,enc_coef):
    en=[]
    r=random.getrandbits(64)
    for i in range(0,len(s2)):
        val=s2calcfun(s1,s2[i],enc_coef)
        val2=encrypt(pub,s2[i])
        val=multime(pub,val,r)
        en.append(addemup(pub, val, val2))
        random.shuffle(en)
    return en


# In[12]:


def outputq3(s1,s2,en):
    output_values=[]
    temp=[]
    for i in range(0,len(s2)):
        a=decrypt(priv,pub,en[i])
        temp.append(a)
    for i in range(0,len(temp)):
        if temp[i] in s1:
            output_values.append(int(temp[i]))
    return output_values


# In[13]:


#priv, pub = generate_keypair(2048)#generate crypto scheme to work on
pets1=[9,32,17,45,98,23,54,234,87] # P1 defines the his set s1
pets2=[19,65,17,54,8,76,29,81,87,36,23]#P2 defines his set s2
def test_functionq3():
    print "running the test function for the intersection of the 2 sets (question 3)"
    alice=enc_function(pets1)          #P1(alice) creates the encrypted coefficients of the polynomial
                                    #and grants access to it to P2 along with the pub value generated above
        
    en=gen_tuples_q3(pets1,pets2,alice)    #P2(bob) is now generating the tuples according to the 
                                    #Two-party HBC protocol for Set Union, and sends them to P1
    
    return outputq3(pets1,pets2,en) 


# In[14]:


print test_functionq3()

