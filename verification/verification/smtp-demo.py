"""Display genuine local SMTP/TLS replies and handler events from the frozen library."""
import asyncio,importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('smtp_wire_checks',Path(__file__).with_name('test_smtp_boundary.py'))
wire=importlib.util.module_from_spec(spec);spec.loader.exec_module(wire)

async def main():
 async with wire.server() as (reader,writer,handler,protocol,context,_):
  print('Local SMTP connection established.',flush=True)
  async def send(command):
   print('Client:',command.decode(),flush=True)
   code,data=await wire.command(reader,writer,command)
   print('Server:',data.decode(errors='replace').rstrip(),flush=True)
   return code
  await send(b'EHLO example.test')
  code=await send(b'STARTTLS')
  if code!=220:return
  await writer.start_tls(context,server_hostname='localhost',ssl_handshake_timeout=3)
  print('TLS handshake completed.',flush=True)
  await send(b'MAIL FROM:<before-greeting@example.test>')
  await send(b'EHLO example.test')
  await send(b'MAIL FROM:<alice@example.test>')
  await send(b'RCPT TO:<bob@example.test>')
  if await send(b'DATA')==354:await send(b'Subject: Local example\r\n\r\nHello\r\n.')
  print('Observed handler events:',handler.events,flush=True)
 print('\nChecking cleartext commands sent with STARTTLS.',flush=True)
 async with wire.server(barrier=True) as (reader,writer,handler,protocol,context,events):
  entered,release,_=events;await wire.ehlo(reader,writer)
  writer.write(b'STARTTLS\r\nMAIL FROM:<prebuffered@example.test>\r\nRCPT TO:<target@example.test>\r\n');await writer.drain()
  await asyncio.wait_for(entered.wait(),3);release.set()
  response=await asyncio.wait_for(reader.read(),3)
  print('Remaining server bytes:',repr(response),flush=True)
  print('Observed handler events:',handler.events,flush=True)

if __name__=='__main__':asyncio.run(main())
