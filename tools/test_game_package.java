package com.totkrecompandroid;
import java.io.*;
import java.nio.*;
import java.util.*;

class PackageTests {
    static int checks;
    static GamePackage.Reader reader(byte[] b) {
        return new GamePackage.Reader() {
            public long length() { return b.length; }
            public void read(long at, byte[] out) throws IOException {
                if (at < 0 || at > b.length - out.length) throw new EOFException();
                System.arraycopy(b, (int)at, out, 0, out.length);
            }
        };
    }
    static byte[] container(boolean hfs, String name, byte[] payload) {
        byte[] names = (name + "\0").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int stride = hfs ? 64 : 24;
        ByteBuffer b = ByteBuffer.allocate(16 + stride + names.length + payload.length).order(ByteOrder.LITTLE_ENDIAN);
        b.put((hfs ? "HFS0" : "PFS0").getBytes()); b.putInt(1); b.putInt(names.length); b.putInt(0);
        b.putLong(0); b.putLong(payload.length); b.putInt(0);
        b.position(16 + stride); b.put(names); b.put(payload); return b.array();
    }
    static void check(boolean ok) { checks++; if (!ok) throw new AssertionError("check " + checks); }
    static void rejects(byte[] b) throws Exception {
        try { GamePackage.entries(reader(b)); throw new AssertionError("accepted bad package"); }
        catch (IOException expected) { checks++; }
    }
    public static void main(String[] args) throws Exception {
        byte[] nsp = container(false, "test.nca", new byte[]{1,2,3});
        List<GamePackage.Entry> e = GamePackage.entries(reader(nsp));
        check(e.size() == 1 && e.get(0).name.equals("test.nca") && e.get(0).size == 3);
        check(nsp[(int)e.get(0).offset] == 1);
        byte[] secure = container(true, "game.nca", new byte[]{4,5,6});
        byte[] root = container(true, "secure", secure);
        byte[] xci = new byte[0xF000 + root.length];
        ByteBuffer.wrap(xci).order(ByteOrder.LITTLE_ENDIAN).position(0x100).put("HEAD".getBytes());
        ByteBuffer.wrap(xci).order(ByteOrder.LITTLE_ENDIAN).putLong(0x130, 0xF000);
        System.arraycopy(root, 0, xci, 0xF000, root.length);
        e = GamePackage.entries(reader(xci)); check(e.get(0).name.equals("game.nca")); check(xci[(int)e.get(0).offset] == 4);
        rejects(new byte[2]); rejects(Arrays.copyOf(nsp, nsp.length-1));
        rejects(container(false, "../escape", new byte[1]));
        byte[] bad = nsp.clone(); ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putLong(16, Long.MAX_VALUE); rejects(bad);
        bad = nsp.clone(); ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putLong(24, Long.MAX_VALUE); rejects(bad);
        bad = nsp.clone(); ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putInt(4, Integer.MAX_VALUE); rejects(bad);
        bad = nsp.clone(); ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putInt(32, -1); rejects(bad);
        bad = nsp.clone(); bad[48] = 65; rejects(bad);
        bad = xci.clone(); ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putLong(0x130, Long.MAX_VALUE); rejects(bad);
        rejects(container(true, "secure", secure));
        // A sparse >4 GiB payload must retain 64-bit offsets and sizes without allocating it.
        byte[] hugeHead = container(false, "large.nca", new byte[0]);
        ByteBuffer.wrap(hugeHead).order(ByteOrder.LITTLE_ENDIAN).putLong(24, 5L << 30);
        GamePackage.Reader huge = new GamePackage.Reader() {
            public long length() { return hugeHead.length + (5L << 30); }
            public void read(long at, byte[] out) { System.arraycopy(hugeHead, (int)at, out, 0, out.length); }
        };
        check(GamePackage.entries(huge).get(0).size == (5L << 30));
        // Synthetic ticket headers: a personalized titlekey block is NOT an encrypted AES title key.
        byte[] ticket = new byte[0x400];
        ByteBuffer.wrap(ticket).order(ByteOrder.BIG_ENDIAN).putInt(0, 0x10004);
        for (int i = 0; i < 16; i++) {
            ticket[0x2a0 + i] = (byte)i;
            ticket[0x180 + i] = (byte)(i + 16);
        }
        GameTicket common = GameTicket.read(ticket);
        check(!common.personalized && common.rightsId.equals("000102030405060708090a0b0c0d0e0f"));
        check(common.encryptedTitleKey.equals("101112131415161718191a1b1c1d1e1f"));
        ticket[0x281] = 1;
        GameTicket personalized = GameTicket.read(ticket);
        check(personalized.personalized && personalized.encryptedTitleKey == null);
        ticket[0x281] = 2;
        try { GameTicket.read(ticket); throw new AssertionError("accepted invalid ticket key type"); }
        catch (IOException expected) { checks++; }
        try { GameTicket.read(new byte[12]); throw new AssertionError("accepted short ticket"); }
        catch (IOException expected) { checks++; }
        // Switch ticket signature headers vary in size. All supported types
        // must locate the same ticket fields relative to their own data offset.
        int[] types = { 0x010000, 0x010001, 0x010002, 0x010003,
                        0x010004, 0x010005, 0x010006 };
        int[] offsets = { 0x240, 0x140, 0x080, 0x240, 0x140, 0x080, 0x040 };
        for (int i = 0; i < types.length; i++) {
            int pos = offsets[i];
            check(GameTicket.dataOffset(types[i]) == pos);
            byte[] variant = new byte[pos + 0x2c0];
            ByteBuffer.wrap(variant).order(ByteOrder.BIG_ENDIAN).putInt(types[i]);
            for (int j = 0; j < 16; j++) {
                variant[pos + 0x40 + j] = (byte)(j + 16);
                variant[pos + 0x160 + j] = (byte)j;
            }
            GameTicket parsed = GameTicket.read(variant);
            check(!parsed.personalized && parsed.rightsId.equals(common.rightsId) &&
                parsed.encryptedTitleKey.equals(common.encryptedTitleKey));
            variant[pos + 0x141] = 1;
            check(GameTicket.read(variant).personalized &&
                GameTicket.read(variant).encryptedTitleKey == null);
            byte[] truncated = Arrays.copyOf(variant, variant.length - 1);
            try { GameTicket.read(truncated); throw new AssertionError("accepted truncated variant"); }
            catch (IOException expected) { checks++; }
        }
        byte[] unknown = new byte[0x400];
        ByteBuffer.wrap(unknown).order(ByteOrder.BIG_ENDIAN).putInt(0x012345);
        try { GameTicket.read(unknown); throw new AssertionError("accepted unknown signature"); }
        catch (IOException expected) { checks++; }
        System.out.println(checks + " package checks passed");
    }
}
