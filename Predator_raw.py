# Predator/Predator.py
from sys import exit
from functools import wraps
from typing import Callable, List, Dict, Optional
from inspect import signature as sig, Parameter, stack as inspect_stack
from psutil import virtual_memory
from aiofiles import open as iopen
from os import path
from mimetypes import guess_type
from asyncio import CancelledError, to_thread, run, sleep
from aiohttp import web
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode, b64decode

p = print

class Configs:
    def __init__(app):
        app.response_headers = {
            'Server': 'Predator',
            'Strict-Transport-Security': 'max-age=63072000; includeSubdomains', 
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(self), microphone=()',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'Date': 'redacted'
        }

system_configs = Configs()

class Instance:
    def __init__(app, **kwargs):
        app.__dict__.update(kwargs)
        
    async def get(app):
        return app.__dict__
 
class Error(Exception):
    def __init__(app, message=None):
        super().__init__(message)
        app.message = str(message)

    def __str__(app) -> str:
        return app.message

class Stream_Response:
    def __init__(app, r, status=200):
        app.r = r
        app.response = web.StreamResponse(
            status=status,
            reason="OK",
            headers=system_configs.response_headers
        )
    
    async def json(app):
        app.response.headers.update({
            'Content-Range': '',
            'Accept-Ranges': 'bytes',
            'Content-Type': "application/json",
        })
        return app.response

    async def text(app):
        app.response.headers.update({
            'Content-Range': '',
            'Accept-Ranges': 'bytes',
            'Content-Type': "text/plain",
        })
        return app.response
        
    async def write(app, content):
        if not app.r.response.prepared:
            await app.r.response.prepare(app.r.request)
        
        if not isinstance(content, (bytes, bytearray)):
            content = content.encode()
        await app.r.response.write(content)
        return app.r

    async def finish(app):
        await app.r.response.write_eof()
        return app.r
             
class Safe:
    def __init__(app, key=0, salt=0):
        app.salt = str(salt) or 'problem'
        app.safe_key = str(key) or 'kim_jong_un'
        app.key = None
        
    def safe_tool_sync(app, og: Instance):
        try:
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
        except Exception as e:
            raise Error(e)
    
    # Asynchronous method
    async def safe_tool(app, og: Instance):
        return await to_thread(app.safe_tool_sync, og)

class Static:
    async def static_file_server(app, r, override_file=0, serve_chunk=0, arg="serve"):
        if not (file := override_file):
            if not (file := r.params.get(arg, 0)):
                raise app.Error("serve parameter is required.")
            file = f"./static/{file}"
        else: file = str(file)
        
        async def meta():
            def _func():
                if not path.exists(file): raise Error("Not found")
                d = Instance(fname = file)
                d.filename = path.basename(d.fname)
                d.file_size = path.getsize(d.fname)
                d.content_type, _ = guess_type(d.fname)
                d.content_disposition = 'inline; filename="{}"'.format(d.filename)
                
                if (range_header := r.headers.get('Range', r.params.get('Range', None))):
                    d.start, d.end = (byte_range := range_header.strip().split('=')[1]).split('-')
                    d.start = int(d.start)
                    d.end = int(d.end) if d.end else d.file_size - 1
                else:
                    d.start, d.end = 0, d.file_size - 1

                d.content_range = f'bytes {d.start}-{d.end}/{d.file_size}' if r.headers.get("Range", None) else ''
                
                d.content_length = str(d.end - d.start + 1)
            
                if not d.content_type:
                    d.content_type = "application/octet-stream"
                    d.content_disposition = 'attachment; filename="{}"'.format(d.filename)
                    
                status = 206 
                if (range_header:=r.headers.get("Range", None)):
                    status = 206
                else:
                    status = 200
                    
                r.stream = Stream_Response(r, status)
                r.response = r.stream.response
                
                r.response.headers.update(
                    {
                        'Content-Range': d.content_range,
                        'Accept-Ranges': 'bytes',
                        'Content-Length': d.content_length,
                        'Content-Type': d.content_type,
                        'Content-Disposition': d.content_disposition
                    }
                )
                return d
            return await to_thread(_func)
            
        d = await meta()
        
        try:
            async with iopen(d.fname, "rb") as f:
                while 1:
                    await f.seek(d.start)
                    if not (chunk := await f.read(serve_chunk or 1024)): break
                    else:
                        d.start += len(chunk)
                        await r.stream.write(chunk)
                
                await r.stream.finish()
            return r
        except Exception as e:
            raise Error(e)

class WebApp(Static):
    def __init__(app):
        Static.__init__(app)
        app.web = web
        app.response_headers = system_configs.response_headers
        app.dev = 1
        app.methods = Instance(methods = {}).methods
        app.Error = Error
        app.Instance = Instance
        app.ddos_protection = 0
        app.throttle_at_ram = 0.20
        app.secure_host = 0
        
    def route(app, func: Callable):
        route_name = func.__name__
        signature = sig(func)

        params = dict(signature.parameters)
        methods_param = params.get("methods", None)
        alt_route = params.get("route", None)
        methods = methods_param.default if methods_param and methods_param.default is not Parameter.empty else ["GET", "POST", "OPTIONS", "PUT", "PATCH", "HEAD", "DELETE"]
        
        if alt_route: route_name = alt_route.default.replace("/", "_")
        
        data = {
            'func': func,
            'params': params,
            'methods': methods,
        }
        
        app.methods[route_name] = data
        return func

    async def log(app, e):
        def _func():
            known_exceps = ["transport", "Task"]
            ins = Instance(fname=inspect_stack()[3].function)
            ins.e, ins.log = str(e), 0

            for a in known_exceps:
                if a in ins.e:
                    pass
                else:
                    ins.log = 1
                    break

            if ins.log:
                str_ = f"[{ins.fname}]:: {ins.e}"
            
                if len(str_) <= 100:
                    pass
                else:
                    str_ = str_[:100]
                p(str_)
                
        await to_thread(_func)
        
    async def gen_request(app, incoming_request):
        if incoming_request is not None:
            async def const_r():
                def get_system_resources():
                    ins = app.Instance()
                    ins.memory_info = virtual_memory()
                    ins.aval_gb = float(f"{ins.memory_info.available / (1024 ** 3):.2f}")
                    return ins
                    
                def _func():
                    request = Instance()
                    request.request = incoming_request
                    request.response = None
                    request.tail = request.request.path
                    request.params = {a:b for a,b in request.request.query.items()}
                    request.headers = {a:b for a,b in request.request.headers.items()}
                    request.method = request.request.method
                    request.ip = request.headers.get('X-Forwarded-For', None) or request.headers.get('X-Real-IP', None) or request.headers.get('Forwarded', None)
                    request.route_name = "_".join(request.tail.split("/"))
                    request.blocked = 0
                    
                    if not "_" in request.route_name: request.route_name = "_"
                    request.full_tail = request.route_name + "?" + "&&".join([f"{a}={b}" for a, b in request.params.items()])
                    
                    p(f"[{request.ip or '127.0.0.1'}] :{request.method}: @{request.tail[:100]}")
                    
                    if app.ddos_protection:
                        ins = get_system_resources()
                        if ins.aval_gb <= app.throttle_at_ram:
                            request.blocked = f"Our server is currently busy, remaining resources are: {ins.aval_gb} GB, try again later when resources are available."
                            
                    if app.secure_host and not request.headers.get("Host", "0").startswith(app.host):
                        request.blocked = "Unidentified Client"
                    return request
                return await to_thread(_func)
            return await const_r()
        
    async def router(app, incoming_request):
        try:
            request = await app.gen_request(incoming_request)
            if request.blocked: raise Error(request.blocked)
            
            if (a := "before_middleware") in app.methods:
                if request.method not in app.methods[a]["methods"]: raise Error("Method not allowed")
                request = await app.methods[a]["func"](request)

            if request.response is None and request.route_name in app.methods:
                if request.method not in app.methods[request.route_name]["methods"]: raise Error("Method not allowed")
                
                request = await app.methods[request.route_name]["func"](request)
                
            if request.response is None:
                if (a := "not_found_method") in app.methods or (a := "handle_all") in app.methods:
                    if request.method not in app.methods[a]["methods"]: raise Error("Method not allowed")
                
                    request = await app.methods[a]["func"](request)

                    if request.response is None:
                        raise Error("Not found")
                else:
                    raise Error("Not found")
            
            if (a := "after_middleware") in app.methods:
                request = await app.methods[a]["func"](request)
        except Error as e: request.response = web.json_response({"detail": str(e)}, status=403)
        except KeyboardInterrupt: pass
        except Exception as e:
            if app.dev:
                msg = str(e)
            else:
                msg = "Unexpected 403"
            try:
                await app.log(e)
                request.response = web.json_response({"detail": msg}, status=403)
            except: pass
        finally:
            try:
                request.response.headers.update(system_configs.response_headers)
            except KeyboardInterrupt: pass
            except Exception as e: pass
            finally:
                return request.response
                
    async def handle(app, request):
        return await app.router(request)
    
    def setup_ssl(app):
        if not path.exists(f"{app.app_config.certfile}") or not path.exists(f"{app.app_config.keyfile}"):
            from os import system
            system(f'openssl req -x509 -newkey rsa:2048 -keyout {app.app_config.keyfile} -out {app.app_config.certfile} -days 365 -nodes -subj "/CN={app.app_config.host}"')
        
        from ssl import create_default_context, Purpose 
        app.app_config.ssl_context = create_default_context(Purpose.CLIENT_AUTH)
        app.app_config.ssl_context.load_cert_chain(certfile=app.app_config.certfile, keyfile=app.app_config.keyfile)
        
    async def run(app, app_config: Instance):
        app.app_config = app_config
        server = web.Server(app.handle)
        server.client_max_size = 1024*1024*1024*1024*1024
        app.app_config.runner = web.ServerRunner(server)
            
        await app.app_config.runner.setup()
        
        if not (ssl_data := app.app_config.__dict__.get("ssl", None)):
            app.app_config.site = web.TCPSite(app.app_config.runner, app.app_config.host, app.app_config.port)
        else:
            app.app_config.certfile, app.app_config.keyfile = ssl_data["certfile"], ssl_data["keyfile"]
            
            await to_thread(app.setup_ssl)
            app.app_config.site = web.TCPSite(app.app_config.runner, app.app_config.host, app.app_config.port, ssl_context=app.app_config.ssl_context)
            
        await app.app_config.site.start()
        
        if ssl_data: prot = "https"
        else: prot = "http"
        await app.log(f"=== Predator Is Serving {app.app_config.host} On {prot}://{app.app_config.host}:{app.app_config.port} ===")
        
        await sleep(100*3600)
        
    def runner(app, app_config: Instance):
        try:
            for a in ["host", "port"]:
                if not app_config.__dict__.get(a, None):
                    raise Error(f"{a} is required.")
                    
            run(app.run(app_config))
        except KeyboardInterrupt: exit()
        except (ConnectionResetError, OSError) as e:
            pass
        except: pass
 
if __name__ == '__main__':
    config = pd.Instance(host="0.0.0.0", port=8000, ssl={"certfile": "cert.pem", "keyfile": "key.pem"})
    wb.runner(config)