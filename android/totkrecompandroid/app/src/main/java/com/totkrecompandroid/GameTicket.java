package com.totkrecompandroid;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Locale;

/**
 * Switch ES ticket header reader. Signature headers have variable lengths;
 * the fields after them must NOT be read at a fixed absolute offset.
 * Does not verify the certificate chain or decrypt personalized RSA title keys.
 */
final class GameTicket {
    final String rightsId;
    final String encryptedTitleKey; // null for personalized tickets
    final boolean personalized;

    private GameTicket(String id, String key, boolean personalized) {
        this.rightsId = id;
        this.encryptedTitleKey = key;
        this.personalized = personalized;
    }

    /** Signed ticket data starts after the signature and its alignment padding. */
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
                    "Assinatura de ticket não reconhecida (tipo 0x%08X).", signatureType));
        }
    }

    static GameTicket read(byte[] ticket) throws IOException {
        if (ticket.length < 4 || ticket.length > 65536)
            throw new IOException("Ticket inválido (tamanho inesperado).");
        int signatureType = ByteBuffer.wrap(ticket).order(ByteOrder.BIG_ENDIAN).getInt();
        int data = dataOffset(signatureType);
        // Complete standard Switch ticket data is 0x2C0 bytes.
        if (ticket.length < data + 0x2c0)
            throw new IOException("Ticket truncado para a assinatura informada.");
        int keyType = ticket[data + 0x141] & 0xff;
        String id = hex(ticket, data + 0x160, 16);
        if (keyType == 0) return new GameTicket(id, hex(ticket, data + 0x40, 16), false);
        if (keyType == 1) return new GameTicket(id, null, true);
        throw new IOException("Tipo de chave de ticket não suportado (" + keyType + ").");
    }

    private static String hex(byte[] b, int start, int count) {
        StringBuilder out = new StringBuilder(count * 2);
        for (int i = start; i < start + count; i++)
            out.append(String.format(Locale.ROOT, "%02x", b[i] & 0xff));
        return out.toString();
    }
}
