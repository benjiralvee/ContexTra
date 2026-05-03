# -*- coding: utf-8 -*-
"""
Created on Thu Feb 13 14:44:55 2020

@author: 16pt20
"""
import random
import math

class Elgamal:
    def __init__(self):
        self.public_key=[]
        self.private_key=0
        
    def __gcd(self, _a, _b):
        if _a < _b: 
            return self.__gcd(_b, _a) 
        elif _a % _b == 0: 
            return _b; 
        else: 
            return self.__gcd(_b, _a % _b) 
        
    def __generate_private_key(self,_value):
        __key = random.randint(math.pow(10,20),_value)
        
        while self.__gcd(_value, __key)!=1:
            __key = random.randint(math.pow(10,20),_value)
        return __key
    
    def __modular_exponent(self,_a, _b, _c): 
        _x = 1
        _y = _a 
  
        while _b > 0: 
            if _b % 2 == 0: 
                _x = (_x * _y) % _c; 
            _y = (_y * _y) % _c 
            _b = int(_b / 2) 
        return _x % _c 
        
    def generate_key(self):
        q=random.randint(math.pow(10,10), math.pow(10,50))
        g=random.randint(2,q)
        a=self.__generate_private_key(q)
        h=self.__modular_exponent(g, a, q)
        self.public_key.append(h)
        self.public_key.append(q)
        self.public_key.append(g)
        self.private_key=str(a).encode(encoding='UTF-8',errors='strict')
        return self.public_key
        
    
    def __convert_msg(self,__msg):
        _str_val=[0]*len(__msg)
        for i in range(0,len(__msg)):
            _str_val[i]=ord(__msg[i])
        return _str_val
        
    def encrypt_message(self, __msg, __key_list):
        q=__key_list[1]
        h=__key_list[0]
        g=__key_list[2]
        _key=self.private_key.decode(encoding='UTF-8',errors='strict')
        s=self.__modular_exponent(h, int(_key), q)
        p=self.__modular_exponent(g, int(_key), q)
        _str_val=self.__convert_msg(__msg)
        
        for _itr in range(0,len(_str_val)):
            _str_val[_itr]=s*_str_val[_itr]
            
                
        return (p,_str_val)
    
    def decrypt_message(self, __msg, __key_list):
        s=__msg[1]
        p=__msg[0]
        q=__key_list[1]
        _original_msg=""
        _key=self.private_key.decode(encoding='UTF-8',errors='strict')
        h=self.__modular_exponent(p, int(_key), q)
        
        for _itr in range(0,len(s)):
            k=int(s[_itr]/h)
            _original_msg=_original_msg+chr(k)
        return _original_msg
            
        
        
        
    
        
        
        
