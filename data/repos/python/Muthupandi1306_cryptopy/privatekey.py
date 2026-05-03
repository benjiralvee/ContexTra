# -*- coding: utf-8 -*-
"""
Created on Wed Mar 11 10:38:27 2020

@author: 16pt20
"""

class privatekey:
    def __init__(self):
        self.rsa=0
        
    def generate_rsa_key(self,p,q,e):
        pin=(p-1)(q-1)
        k=2222
        d=(k*pin +1)/e
        self.rsa=d

    def get_key(self):
        return self.rsa
        
