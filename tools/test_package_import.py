"""Host-only tests; no game files or real keys. Does not validate an Android APK."""
import pathlib
import subprocess
import tempfile

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
