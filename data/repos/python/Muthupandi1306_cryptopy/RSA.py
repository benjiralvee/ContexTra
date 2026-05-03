# -*- coding: utf-8 -*-
"""
Created on Thu Mar  5 14:50:25 2020

@author: 16pt20
"""
import publickey as pub
import privatekey as pri

class RSA:
    
    def __init__(self):
        self.pub_k=pub.publickey()
        self.priv_k=pri.privatekey()
        self.open_key=0
    
    def generate_key(self):
        self.open_key=self.pub_k.generate_RSA_key(self.priv_k)
    
    def encrypt_message(self,open_keys,msg):
        n=open_keys[0]
        e=open_keys[1]
        msg=list(msg)
        encrypted_msg=[]
        for i in msg:
            k=ord(i)
            val=(k**e)%n
            encrypted_msg.append(val)
        return encrypted_msg

    def decrypt_message(self,msg):
        d=self.priv.get_key()
        n=self.open_key[0]
        p_msg=[]
        for i in msg:
            val=(i**d)%n
            p_msg.append(chr(val))
        p_msg="".join(p_msg)
        return p_msg
            
        
        
        
        
    

