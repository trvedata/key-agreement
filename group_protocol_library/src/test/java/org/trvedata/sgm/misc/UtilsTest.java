package org.trvedata.sgm.misc;

import org.junit.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

public class UtilsTest {

    @Test
    public void testSecureRandom_whenGivenPositiveByteLength_thenReturnsArrayOfLength() {
        final byte[] actual = Utils.getSecureRandomBytes(42);
        assertThat(actual).hasSize(42);
    }

    @Test
    public void testHashFunctions_whenGivenMultipleArrays_thenSameAsCallingWithOne() {
        final String text1 = "Hello ";
        final String text2 = "World";
        final String text3 = "!";

        final byte[] hash1 = Utils.hash(text1.getBytes(), text2.getBytes(), text3.getBytes());
        final byte[] hash2 = Utils.hash(text1, text2.getBytes(), text3.getBytes());
        final byte[] hash3 = Utils.hash((text1 + text2 + text3).getBytes());

        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash2).isEqualTo(hash3);
    }

    @Test
    public void testAeadCrypt_whenGivenEmptyMessage_thenEncryptAndDecryptCorrect() {
        final byte[] plaintext = "".getBytes();
        final byte[] associatedData = "".getBytes();
        final byte[] key = "key".getBytes();

        final byte[] actual = aeadEncryptThenDecrypt(plaintext, associatedData, key);
        assertThat(actual).isEqualTo(plaintext);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAeadCrypt_whenGivenEmptyKey_thenThrow() {
        final byte[] plaintext = "".getBytes();
        final byte[] associatedData = "".getBytes();
        final byte[] key = "".getBytes();

        final byte[] actual = aeadEncryptThenDecrypt(plaintext, associatedData, key);
        assertThat(actual).isEqualTo(plaintext);
    }

    @Test
    public void textAeadCrypt_whenGivenAllArguments_thenEncryptAndDecryptCorrect() {
        final byte[] plaintext = "plaintext".getBytes();
        final byte[] associatedData = "ad".getBytes();
        final byte[] key = "key".getBytes();

        final byte[] actual = aeadEncryptThenDecrypt(plaintext, associatedData, key);
        assertThat(actual).isEqualTo(plaintext);
    }

    @Test
    public void textAeadCrypt_whenMessageTruncated_thenDecryptFails() {
        final byte[] plaintext = "plaintext".getBytes();
        final byte[] associatedData = "ad".getBytes();
        final byte[] key = "key".getBytes();

        final byte[] actual = aeadEncryptThenDecrypt(
                plaintext,
                associatedData,
                key,
                message -> Arrays.copyOf(message, message.length - 1));

        assertThat(actual).isNull();
    }

    @Test
    public void textAeadCrypt_whenMessageBitFlipped_thenDecryptFails() {
        final byte[] plaintext = "plaintext".getBytes();
        final byte[] associatedData = "ad".getBytes();
        final byte[] key = "key".getBytes();

        final byte[] actual = aeadEncryptThenDecrypt(
                plaintext,
                associatedData,
                key,
                message -> {
                    message[0] ^= 0x01;
                    return message;
                });

        assertThat(actual).isNull();
    }

    private byte[] aeadEncryptThenDecrypt(final byte[] plaintext, final byte[] associatedData, final byte[] key) {
        return aeadEncryptThenDecrypt(plaintext, associatedData, key, null);
    }

    private byte[] aeadEncryptThenDecrypt(
            final byte[] plaintext,
            final byte[] associatedData,
            final byte[] key,
            final InterferenceCallback interferenceCallback) {
        byte[] ciphertext = Utils.aeadEncrypt(plaintext, associatedData, key, true);

        if (interferenceCallback != null) {
            ciphertext = interferenceCallback.interfere(ciphertext);
        }

        return Utils.aeadDecrypt(ciphertext, key);
    }

    private interface InterferenceCallback {
        byte[] interfere(final byte[] message);
    }

}
