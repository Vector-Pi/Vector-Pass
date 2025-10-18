import random
import time
from typing import List, Dict 
class Pass_Gen:
    def pwd_gen(self, length=16):
        uppercase_letters = [chr(x) for x in range(ord('A'), ord('Z')+1)]
        lowercase_letters = [chr(x) for x in range(ord('a'), ord('z')+1)] 
        digits = [str(x) for x in range(10)]
        special_characters = ['@','#', '!', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', '|', '\\', ':', ';', '•', '<', '>', '?']
        all_ch = []
        all_ch.extend(uppercase_letters)
        all_ch.extend(lowercase_letters)
        all_ch.extend(digits)
        all_ch.extend(special_characters)
        random.shuffle(all_ch)
        Password = []
        missing_chars = []
        for m in all_ch:
            random.randint(0,int(len(all_ch)))
            if int(len(set(Password))) < int(length):
                if m.isupper() and not any(char.isupper() for char in Password):
                    Password.append(m)
                elif m.islower() and not any(char.islower() for char in Password):
                    Password.append(m)
                elif m.isdigit() and not any(char.isdigit() for char in Password):
                    Password.append(m)
                elif m in special_characters and not any(char in special_characters for char in Password):
                    Password.append(m)
                else:
                    missing_chars.append(m)
        
        if len(missing_chars) > 0:
            for char in missing_chars:
                Password.append(char)
        
        random.shuffle(Password)
        
        Password = ''.join(Password)
        
        if int(len(Password)) > int(length):
            while int(len(Password)) > int(length):
                Password = Password[:-1]
            #print(Password)  
        
        if int(len(Password)) == int(length):
            time.sleep(1)
            #print("Your Password is " + Password)
            print("Your Password is : ", Pass_Gen.improve_password_strength(Password))
            return Password



    def improve_password_strength(password):
        import random

        if len(password) < 6:
            print("Password must be at least 6 characters long!")
            Pass_Gen.pwd_gen(6)
        else:
            uppercase_present = any(char.isupper() for char in password)
            lowercase_present = any(char.islower() for char in password)
            digit_present = any(char.isdigit() for char in password)
            special_present = any(char in ['@','#', '!', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', '|', '\\', ':', ';', '•', '<', '>', '?'] for char in password)

            if not uppercase_present:
                password += random.choice([chr(x) for x in range(ord('A'), ord('Z')+1)])
            if not lowercase_present:
                password += random.choice([chr(x) for x in range(ord('a'), ord('z')+1)])
            if not digit_present:
                password += random.choice([str(x) for x in range(10)])
            if not special_present:
                password += random.choice(['@','#', '!', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', '|', '\\', ':', ';', '•', '<', '>', '?'])

            password = ''.join(set(password))  # Remove repeated characters
            return password
        
        
        
if __name__ == "__main__":
    print("Enter Required Length Of Characters:")
    length = int(input())
    password = Pass_Gen.pwd_gen(length)