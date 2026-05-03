# -*- coding: utf-8 -*-
"""
Created on Wed Mar 11 10:31:03 2020

@author: 16pt20
"""

import MRT as mt
import random

class publickey:
    def __init__(self):
        self.key=[]
        self.RSA_key=[]
        
    def __gcd(self, _a, _b):
        if _a < _b: 
            return self.__gcd(_b, _a) 
        elif _a % _b == 0: 
            return _b; 
        else: 
            return self.__gcd(_b, _a % _b)
    
    def generate_RSA_key(self,pri_key):
        primeno=mt.MRT()
        #pri_key=privatekey.privatekey()
        p=primeno.generate_random_prime()
        q=p
        while p==q:
            q=primeno.generate_random_prime()
        n=p*q
        pin=(p-1)*(q-1)
        e=random.randint(1,pin)
        while self.__gcd(e,pin)!=1:
            e=random.randint(1,pin)
        pri_key.generate_rsa_key(p,q,e)
        self.RSA_key.append(n)
        self.RSA_key.append(e)
        return self.get_rsa_key()
    
    def get_rsa_key(self):
        return self.RSA_key
        
        