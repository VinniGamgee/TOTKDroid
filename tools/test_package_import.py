"""Host-only tests; no game files or real keys. Does not validate an Android APK."""
import pathlib
import subprocess
import tempfile
import os
import socket
import struct
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
def run(*args):
    subprocess.run(args, cwd=ROOT, check=True)
with tempfile.TemporaryDirectory() as tmp:
    java = ROOT / 'android/totkrecompandroid/app/src/main/java/com/totkrecompandroid'
    run('java', '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-d', tmp,
        str(java / 'GamePackage.java'), str(java / 'GameTicket.java'), 'tools/test_game_package.java')
    run('java', '-cp', tmp, 'com.totkrecompandroid.PackageTests')
    binary = str(pathlib.Path(tmp) / 'slice-test')
    run('gcc', '-D_FILE_OFFSET_BITS=64', '-Iandroid/package_import',
        'tools/test_package_slice.c', 'android/package_import/slice.c', '-o', binary)
    with tempfile.NamedTemporaryFile(dir=tmp) as f:
        f.seek(5 * 1024**3)
        f.write(b'abc')
        f.flush()
        run(binary, f'slice:{5 * 1024**3}:3:{f.name}')
    print('Bounded slices: >4 GiB offset, EOF and invalid seek passed')

    # Exercise the real descriptor-passing protocol used on Android. The
    # receiver must read the sparse package without using a parent /proc fd.
    with tempfile.NamedTemporaryFile(dir=tmp) as f:
        f.seek(5 * 1024**3)
        f.write(b'abc')
        f.flush()
        name = 'totkdroid-test-' + str(os.getpid())
        address = '\0' + name
        errors = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(address)
            listener.listen(1)
            def handoff():
                try:
                    with listener.accept()[0] as client:
                        opened = os.open(f.name, os.O_RDONLY)
                        try:
                            client.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                    struct.pack('i', opened))])
                        finally:
                            os.close(opened)
                except Exception as e:
                    errors.append(e)
            thread = threading.Thread(target=handoff, daemon=True)
            thread.start()
            run(binary, f'slice:{5 * 1024**3}:3:fdpass:{name}')
            thread.join(10)
            assert not thread.is_alive() and not errors, errors
    print('Descriptor passing: sparse 5 GiB package through SCM_RIGHTS passed')

    # Header-only scan of a synthetic, unencrypted NCA3: it cannot extract or
    # rely on content title keys just to identify the Program Title ID.
    import subprocess as sp
    import shutil
    import hashlib
    import json
    if shutil.which('cmake'):
        builder = pathlib.Path(tmp) / 'hactool-build'
        run('cmake', '-S', 'android/package_import', '-B', str(builder))
        run('cmake', '--build', str(builder), '-j', '2')
        hactool = builder / 'libpackage_import.so'
        keyset = pathlib.Path(tmp) / 'prod.keys'
        keyset.write_text('# synthetic keyset for an unencrypted NCA3 header\n')
        nca = bytearray(0xC00)
        nca[0x200:0x204] = b'NCA3'
        nca[0x205] = 0
        struct.pack_into('<Q', nca, 0x210, 0x0100F2C0115B6000)
        fake = pathlib.Path(tmp) / 'fake-nca.pkg'
        fake.write_bytes(b'X' * 4096 + nca)
        completed = sp.run([str(hactool), '--totkdroid-header-only', '-t', 'nca',
                            '-k', str(keyset), f'slice:4096:3072:{fake}'],
                           cwd=ROOT, check=True, capture_output=True, text=True)
        assert 'Title ID: 0100f2c0115b6000' in completed.stdout, completed.stdout
        assert 'Content Type: Program' in completed.stdout, completed.stdout
        assert 'prod.keys does not exist' not in completed.stdout, completed.stdout
        print('Header-only NCA scan: title, content type, and explicit keyset passed')
