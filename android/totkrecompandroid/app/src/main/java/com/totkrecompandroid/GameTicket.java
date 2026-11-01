package com.totkrecompandroid;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Locale;

/**
 * Reads Nintendo Switch ES ticket metadata and the encrypted common title key.
 * Never decrypts a personalized ticket or verifies the signature certificate.
 */
final class GameTicket {
    final String rightsId;
    final String encryptedTitleKey; // null for personalized tickets
    final boolean personalized;
    final boolean strippedSignature;

    private GameTicket(String id, String key, boolean personalized, boolean strippedSignature) {
        this.rightsId = id;
        this.encryptedTitleKey = key;
        this.personalized = personalized;
        this.strippedSignature = strippedSignature;
    }

    /** Signed ticket data follows the signature and its alignment padding. */
    static int dataOffset(int signatureType) throws IOException {
        switch (signatureType) {
            case 0x010000: // RSA-4096 / SHA-1
            case 0x010003: // RSA-4096 / SHA-256
                return 0x240;
            case 0x010001: // RSA-2048 / SHA-1
            case 0x010004: // RSA-2048 / SHA-256
                return 0x140;
            case 0x010002: // ECDSA / SHA-1
            case 0x010005: // ECDSA / SHA-256
                return 0x080;
            case 0x010006: // HMAC-SHA1
                return 0x040;
            default:
                throw new IOException(String.format(Locale.ROOT,
                    "Assinatura de ticket desconhecida (0x%08X).", signatureType));
        }
    }

    static GameTicket read(byte[] ticket) throws IOException {
        if (ticket.length < 4 || ticket.length > 65536)
            throw new IOException("Tamanho inválido de ticket (" + ticket.length + " bytes).");
        int signatureType = ByteBuffer.wrap(ticket).order(ByteOrder.BIG_ENDIAN).getInt();
        int data;
        boolean stripped = false;
        try {
            data = dataOffset(signatureType);
        } catch (IOException unknownSignature) {
            // Some exporters write just the 0x2C0-byte ES ticket body. Only
            // accept the exact documented body length and a valid Switch
            // ticket version, key type and nonzero Rights ID. Never try to
            // decrypt a console-personalized ticket or guess a key.
            if (ticket.length != 0x2c0 || (ticket[0x140] & 0xff) != 2)
                throw unknownSignature;
            data = 0;
            stripped = true;
        }
        if (ticket.length < data + 0x2c0)
            throw new IOException("Ticket incompleto: " + ticket.length +
                    " bytes; esperado pelo menos " + (data + 0x2c0) + ".");
        int version = ticket[data + 0x140] & 0xff;
        int keyType = ticket[data + 0x141] & 0xff;
        if (version != 2)
            throw new IOException("Versão de ticket não suportada (" + version + ").");
        if (keyType != 0 && keyType != 1)
            throw new IOException("Tipo de chave do ticket não suportado (" + keyType + ").");
        String id = hex(ticket, data + 0x160, 16);
        if (id.equals("00000000000000000000000000000000"))
            throw new IOException("Ticket sem Rights ID válido.");
        if (keyType == 1)
            return new GameTicket(id, null, true, stripped);
        String key = hex(ticket, data + 0x40, 16);
        if (key.equals("00000000000000000000000000000000"))
            throw new IOException("Ticket comum sem chave de título preenchida.");
        return new GameTicket(id, key, false, stripped);
    }

    private static String hex(byte[] b, int start, int count) {
        StringBuilder out = new StringBuilder(count * 2);
        for (int i = start; i < start + count; i++)
            out.append(String.format(Locale.ROOT, "%02x", b[i] & 0xff));
        return out.toString();
    }
}
