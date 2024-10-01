from aiofiles import open as iopen
from asyncio import run, to_thread
from os.path import exists
from os import remove
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode, b64decode

p = print

class Instance:
    async def __update__(app, **kwargs):
        app.__dict__.update(kwargs)
        
    async def get(app):
        return app.__dict__
 
class Error(Exception):
    def __init__(app, message=None):
        super().__init__(message)
        app.message = str(message)

    def __str__(app) -> str:
        return app.message

class Safe(object):
    @classmethod
    async def init(cls, **kwargs):
        app = cls()
        for key, value in kwargs.items():
            setattr(app, key, value)
        return app
        
    async def safe_tool(app, og: Instance):
        def func():
            # All synchronous operations happen here
            if not app.key: app.key = PBKDF2(app.safe_key.encode(), app.salt.encode(), dkLen=16)
                
            cipher = AES.new(app.key, AES.MODE_EAX)
            if (data := og.__dict__.get("encrypt", 0)):
                if not isinstance(data, (bytearray, bytes,)): data = data.encode()
                ciphertext, tag = cipher.encrypt_and_digest(data)
                
            elif (data := og.__dict__.get("decrypt", 0)):
                try: data = data.replace(' ', '+')
                except: pass
                data = b64decode(data)
                nonce = data[:16]
                tag = data[16:32]
                ciphertext = data[32:]
                cipher = AES.new(app.key, AES.MODE_EAX, nonce=nonce)
                return cipher.decrypt_and_verify(ciphertext, tag)
            else:
                raise Error("Unidentified request")

            # Encoding the nonce (16 bytes), tag (16 bytes), and ciphertext for storage or transmission.
            # This is critical for later decryption.
            return b64encode(cipher.nonce + tag + ciphertext)
        return await to_thread(func)
        
class Main(object):
    open_file = None
    @classmethod
    async def init(cls, **kwargs):
        app = cls()
        for key, value in kwargs.items():
            setattr(app, key, value)
            
        # Set the safe too
        app.safe = await Safe.init(**kwargs)
        return app
    
    async def decode(app, chunk):
        try:
            chunk = chunk.decode("utf-8")
            return chunk
        except UnicodeDecodeError as e:
            p(e)

    async def save(app, chunk):
        try:
            if not app.open_file:
                if exists(app.target_location):
                    if app.__dict__.get("delete_target", None):
                        remove(app.target_location)
                app.open_file = await iopen(app.target_location, "ab")
            
            data = Instance()
            if app.todo == "encrypt":
                data.encrypt = chunk
            else:
                data.decrypt = chunk
            
            chunk = await app.safe.safe_tool(data)
            if data.__dict__.get("encrypt",  None):
                p("Data encrypted")
            else:
                p("Data decrypted")
                
            await app.open_file.write(chunk)
        except UnicodeEncodeError as e:
            p(e)

    async def method2(app):
        chunk = b""
        async with iopen(app.parent_location, "rb") as r:
            while 1:
                if not (i := await r.read(app.max_chunk)):
                    if app.open_file:
                        await app.open_file.close()
                        app.open_file = None
                    break
                else:
                    chunk += i
        await app.save(chunk)
        
    async def method1(app):
        await app.method2()
        
async def main(**kwargs):
    try:
        app = await Main.init(**kwargs)
        await app.method1()
    except KeyboardInterrupt:
        exit("KeyboardInterrupted!")
    except Exception as e:
        p(e)
    
if __name__ == "__main__":
    run(
        main(
            parent_location = input("Enter parent file.( e.g Encrypted_Predator.py ): "),
            target_location = input("Enter target file.( e.g Decrypted_Predator.py ): "),
            todo = input("Enter what you want to do.( e.g encrypt ): "),
            delete_target = True,
            max_chunk = 50,
            salt = input("Enter Salt key: "),
            safe_key = input("Enter Safe key: "),
            key = None
        )
    )
