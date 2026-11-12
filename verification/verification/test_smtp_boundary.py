"""Independent protocol tests. Run against a frozen replay, never the model workspace."""
import asyncio, base64, ssl
from contextlib import asynccontextmanager, suppress
import pytest, trustme
from aiosmtpd.smtp import SMTP, AuthResult
from aiosmtpd.controller import Controller

class Handler:
 def __init__(self):self.events=[]
 async def handle_MAIL(self,srv,session,envelope,address,options):
  self.events.append(('MAIL',address,session.ssl is not None));envelope.mail_from=address;return '250 OK'
 async def handle_RCPT(self,srv,session,envelope,address,options):
  self.events.append(('RCPT',address,session.ssl is not None));envelope.rcpt_tos.append(address);return '250 OK'
 async def handle_DATA(self,srv,session,envelope):self.events.append(('DATA',bytes(envelope.content)));return '250 OK'
 def auth(self,srv,session,envelope,mechanism,data):self.events.append(('AUTH',session.ssl is not None));return AuthResult(success=True,auth_data=None)

async def reply(reader):
 lines=[]
 while True:
  line=await asyncio.wait_for(reader.readline(),3)
  if not line:return 0,b''.join(lines)
  lines.append(line)
  if len(line)<4 or line[3:4]!=b'-':return int(line[:3]),b''.join(lines)

async def command(reader,writer,data):
 writer.write(data+b'\r\n');await writer.drain();return await reply(reader)

@asynccontextmanager
async def server(strict=True,barrier=False,timeout=5):
 loop=asyncio.get_running_loop();ca=trustme.CA();cert=ca.issue_cert('localhost')
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);cert.configure_cert(context)
 client=ssl.create_default_context();ca.configure_trust(client)
 handler=Handler();protocols=[];entered=asyncio.Event();release=asyncio.Event();received=asyncio.Event()
 class Protocol(SMTP):
  async def smtp_STARTTLS(self,arg):
   if barrier:entered.set();await release.wait()
   return await super().smtp_STARTTLS(arg)
  def data_received(self,data):super().data_received(data);received.set()
 def factory():
  options=dict(tls_context=context,auth_require_tls=False,authenticator=handler.auth,timeout=timeout)
  if strict is not None:options['strict_starttls']=strict
  p=Protocol(handler,**options);protocols.append(p);return p
 listener=await loop.create_server(factory,'127.0.0.1',0)
 reader,writer=await asyncio.open_connection('127.0.0.1',listener.sockets[0].getsockname()[1])
 assert (await reply(reader))[0]==220
 try:yield reader,writer,handler,protocols[0],client,(entered,release,received)
 finally:
  release.set();writer.close()
  with suppress(Exception):await writer.wait_closed()
  listener.close();await listener.wait_closed()
  for p in protocols:
   if p.transport:p.transport.close()
  await asyncio.sleep(.02)

async def ehlo(reader,writer):assert (await command(reader,writer,b'EHLO example.test'))[0]==250
async def upgrade(reader,writer,client):
 assert (await command(reader,writer,b'STARTTLS'))[0]==220
 await writer.start_tls(client,server_hostname='localhost',ssl_handshake_timeout=3)

@pytest.mark.parametrize('strict',[True,False,None])
def test_normal_tls_and_delivery(strict):
 async def scenario():
  async with server(strict=strict) as (r,w,h,p,c,_):
   await ehlo(r,w);await upgrade(r,w,c);await ehlo(r,w)
   assert (await command(r,w,b'MAIL FROM:<alice@example.test>'))[0]==250
   assert (await command(r,w,b'RCPT TO:<bob@example.test>'))[0]==250
   assert (await command(r,w,b'DATA'))[0]==354
   assert (await command(r,w,b'hello\r\n.'))[0]==250
   assert [e[0] for e in h.events]==['MAIL','RCPT','DATA']
   assert h.events[0][2] and h.events[1][2]
 asyncio.run(scenario())

@pytest.mark.parametrize('mode',['same-packet','split-command','during-transition'])
def test_prebuffered_cleartext_is_never_replayed(mode):
 async def scenario():
  async with server(barrier=True) as (r,w,h,p,c,events):
   entered,release,received=events;await ehlo(r,w)
   payload=b'MAIL FROM:<injected@example.test>\r\nRCPT TO:<target@example.test>\r\n'
   prefix=payload if mode=='same-packet' else payload[:2] if mode=='split-command' else b''
   w.write(b'STARTTLS\r\n'+prefix);await w.drain();await asyncio.wait_for(entered.wait(),3)
   if mode!='same-packet':
    received.clear();w.write(payload[len(prefix):]);await w.drain();await asyncio.wait_for(received.wait(),3)
   assert bytes(p._reader._buffer).startswith(b'MAIL')
   release.set()
   data=await asyncio.wait_for(r.read(),3)
   assert data==b'' or all(line[:3] not in (b'250',b'354') for line in data.splitlines())
   assert h.events==[]
   assert p.transport is None or p.transport.is_closing()
 asyncio.run(scenario())

@pytest.mark.parametrize('wire_command',[b'MAIL FROM:<alice@example.test>',b'AUTH PLAIN AGFsaWNlAHBhc3M=',b'RCPT TO:<bob@example.test>'])
def test_tls_requires_fresh_ehlo(wire_command):
 async def scenario():
  async with server() as (r,w,h,p,c,_):
   await ehlo(r,w);await upgrade(r,w,c)
   code,_=await command(r,w,wire_command)
   assert code>=500 and h.events==[]
 asyncio.run(scenario())

def test_tls_discards_auth_and_pending_envelope():
 async def scenario():
  async with server() as (r,w,h,p,c,_):
   await ehlo(r,w)
   assert (await command(r,w,b'AUTH PLAIN AGFsaWNlAHBhc3M='))[0]==235
   assert (await command(r,w,b'MAIL FROM:<old@example.test>'))[0]==250
   assert (await command(r,w,b'RCPT TO:<old-target@example.test>'))[0]==250
   await upgrade(r,w,c)
   assert p.session.authenticated is not True and p.session.auth_data is None
   assert not p.session.host_name and not p.envelope.mail_from and not p.envelope.rcpt_tos
   await ehlo(r,w)
   assert (await command(r,w,b'RCPT TO:<new@example.test>'))[0]==503
   assert not any(e[0]=='DATA' for e in h.events)
 asyncio.run(scenario())

def test_helo_cannot_replace_required_post_tls_ehlo():
 async def scenario():
  async with server() as (r,w,h,p,c,_):
   await ehlo(r,w);await upgrade(r,w,c)
   assert (await command(r,w,b'HELO example.test'))[0]==250
   assert (await command(r,w,b'MAIL FROM:<alice@example.test>'))[0]>=500
   assert h.events==[]
   await ehlo(r,w)
   assert (await command(r,w,b'MAIL FROM:<alice@example.test>'))[0]==250
 asyncio.run(scenario())

def test_prebuffered_auth_is_not_logged(caplog):
 import logging
 credential=base64.b64encode(b'\0local-test-user\0only-a-test-password')
 async def scenario():
  async with server(barrier=True) as (r,w,h,p,c,events):
   entered,release,_=events;await ehlo(r,w)
   w.write(b'STARTTLS\r\nAUTH PLAIN '+credential+b'\r\n');await w.drain()
   await asyncio.wait_for(entered.wait(),3);release.set()
   await asyncio.wait_for(r.read(),3)
   assert h.events==[]
 with caplog.at_level(logging.DEBUG):asyncio.run(scenario())
 assert credential.decode() not in caplog.text and 'only-a-test-password' not in caplog.text

@pytest.mark.parametrize('failure',['invalid-clienthello','disconnect','cancel','timeout'])
def test_failed_handshake_cannot_resume_plain_smtp(failure):
 async def scenario():
  async with server(timeout=.4 if failure=='timeout' else 5) as (r,w,h,p,c,_):
   await ehlo(r,w);assert (await command(r,w,b'STARTTLS'))[0]==220
   if failure=='invalid-clienthello':w.write(b'MAIL FROM:<injected@example.test>\r\n');await w.drain()
   elif failure=='disconnect':w.close()
   elif failure=='cancel':p._handler_coroutine.cancel()
   if failure!='disconnect':
    with suppress(ConnectionResetError,ssl.SSLError):
     remaining=await asyncio.wait_for(r.read(),3)
     assert b'250' not in remaining
   else:
    with suppress(Exception):await w.wait_closed()
    await asyncio.sleep(.05)
   assert h.events==[]
   assert p._original_transport is None or p._original_transport.is_closing()
 asyncio.run(scenario())

def test_controller_forwards_explicit_option():
 async def scenario():
  controller=Controller(Handler(),loop=asyncio.get_running_loop(),strict_starttls=True)
  protocol=controller.factory()
  assert isinstance(protocol,SMTP)
 asyncio.run(scenario())
