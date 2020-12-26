# -*- coding: utf-8 -*-
import os
import sys
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def get_dir(): # ファイルを取得
    path = './'
    files = []
    
    for filename in os.listdir(path):
        if os.path.isfile(os.path.join(path, filename)): # ファイルのみ取得
            files.append(filename)
    print ('ファイル一覧 >> ')
    
    for i in files:
        print (str(i) + '. ' + files[i])
        
    return(files)

def file_number(num):
    global files
    return (files[num])
    
def generate_key():
    """鍵の生成"""
    print ('Type a Password.')
    password_provided = input('>> ')
    password = password_provided.encode()

    salt = b"\xb2\xb2\x92\xd9\x15\xe3\xeaBp\x11\xa4\xc8r\xf7lB" #from os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
    fernet = Fernet(key)
    return (key)

class crypto():    
    def encrypto(self, key, input_file):
        """暗号化"""
        with open(input_file, 'rb') as f:
            self.data = f.read()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(self.data)

        with open(input_file, 'wb') as f:
            self.data = f.write(encrypted)
        #print ('>> ' + input_file + ' is encrypted')
        print ('>> ' + input_file + ' は正常に暗号化されました.')
        file_name, ex = os.path.splitext(input_file)
        new_name = (file_name + '.encrypted' + ex)
        os.rename(input_file, new_name)
        return 0
    
    def decrypto(self, key, input_file):
        """復号化"""
        old_file = input_file
        file_name, ex = os.path.splitext(input_file)
        file_name, encrypted = os.path.splitext(file_name)
        new_name = (file_name + ex)
        
        if encrypted == '.encrypted':        
            try:
                with open(input_file, 'rb') as f:
                    self.data = f.read()
                fernet = Fernet(key)
                decrypted = fernet.decrypt(self.data)

                with open(input_file, 'wb') as f:
                    self.data = f.write(decrypted)
                #print ('>> ' + old_file + ' is decrypted')
                os.rename(input_file, new_name)
                print ('>> ' + old_file + ' は正常に復号化されました.')
                return 0
    
            except:
                #input ('Password is Wrong!!')
                input ('パスワードが間違っています. Enterキーを押して、終了してください. ')
            
        else:
            print ('ファイルは暗号化されていません. ')

def select_crypto(num, key, input_file):
    c = crypto()
    if num == 1:
        c.encrypto(key, input_file) 
    elif num == 2:
        c.decrypto(key, input_file)
    else:
        #print ('Type 1 or 2')
        print ('1か2を入力してください >> ')

def main():
    get_dir()
    num = input('select the file number >> ')
    input_file = file_number(int(num))
    key = generate_key()
    selecter = input('select 1:encrypto or 2:decrypto >> ')
    select_crypto(int(selecter), key, input_file)
    
main()    