# -*- coding: utf-8 -*-
"""
Created on Tue Mar 10 18:13:24 2020

@author: 16pt20
"""
import random
import math

class MRT:
    
    def __init__(self):
        pass
    
    
    def power(self,x,y,p):
        result=1
        x=x%p
        while y>0:
            if y>0:
                result=(result*x)%p
            y=y>>1
            x=(x*x)%p
        return result
    
    def __millerTest(self,d,n):
        a = 2 + random.randint(1, n - 4)
        x = self.power(a, d, n)
        if (x == 1 or x == n - 1): 
            return 1
        
        while d!=n-1:
            x=(x*x)%n
            d=d*2
            
            if x==1:
                return 0
            if x==n-1:
                return 1
        return 0
        
    def __isPrime(self,n,k):
        
        if n<=1 or n==4:
            return 0
        if n<=3:
            return 1
        __iter=n-1
        
        while __iter%2==0:
            __iter//=2
        
        for i in range(k):
            if(self.__millerTest(__iter,n)==0):
                return 0;
        return 1
        
    def generate_random_prime(self):
        value=random.randint(math.pow(10,3), math.pow(10,6))
        iteration=20
        while self.__isPrime(value,iteration)!=1:
            value=random.randint(math.pow(10,5), math.pow(10,6))
        return value
        
            
    
    
