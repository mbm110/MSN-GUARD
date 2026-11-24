"""Exercise packaged Android PIE linker without contacting Lantern servers."""
import glob,json,pathlib,subprocess,zipfile

def run(*args):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
    return {'exit':p.returncode,'output':p.stdout[-8000:]}

apk=next(p for p in glob.glob('diagnostic-apks/*.apk') if 'x86_64' in p)
root=pathlib.Path('startup-native');root.mkdir(exist_ok=True)
with zipfile.ZipFile(apk) as z:
    for name in ['liblantern.so','libc++_shared.so']:
        (root/name).write_bytes(z.read('lib/x86_64/'+name))
print(run('adb','shell','mkdir','-p','/data/local/tmp/lantern-smoke'))
for f in root.iterdir():
    print(run('adb','push',str(f),'/data/local/tmp/lantern-smoke/'+f.name))
print(run('adb','shell','chmod','755','/data/local/tmp/lantern-smoke/liblantern.so'))
results={}
results['without_library_path']=run('adb','shell','cd /data/local/tmp/lantern-smoke && ./liblantern.so -h')
results['with_library_path']=run('adb','shell','cd /data/local/tmp/lantern-smoke && LD_LIBRARY_PATH=/data/local/tmp/lantern-smoke ./liblantern.so -h')
pathlib.Path('lantern-startup-results.json').write_text(json.dumps(results,indent=2))
print(json.dumps(results,indent=2))
assert results['with_library_path']['exit']==0, 'Packaged sidecar cannot even reach flag parsing on Android'
assert 'control-socket' in results['with_library_path']['output']
