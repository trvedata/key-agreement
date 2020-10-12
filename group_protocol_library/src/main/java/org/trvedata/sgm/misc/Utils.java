package org.trvedata.sgm.misc;

import org.apache.thrift.TBase;
import org.apache.thrift.TDeserializer;
import org.apache.thrift.TException;
import org.apache.thrift.TSerializer;
import org.apache.thrift.protocol.TCompactProtocol;
import org.pcollections.HashPMap;
import org.pcollections.TreePVector;
import org.trvedata.sgm.message.AeadMessage;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Encapsulation of common cryptographic primitives
 */
public class Utils {
    public static byte[] getSecureRandomBytes(final int byteLength) {
        final byte[] result = new byte[byteLength];
        new SecureRandom().nextBytes(result);
        return result;
    }

    public static byte[] serialize(final TBase thrift) {
        final TSerializer serializer = new TSerializer(new TCompactProtocol.Factory());
        try {
            return serializer.serialize(thrift);
        } catch (TException exc) {
            throw new RuntimeException(exc);
        }
    }

    public static <TObject extends TBase> void deserialize(final TObject object, final byte[] data) throws TException {
        final TDeserializer deserializer = new TDeserializer(new TCompactProtocol.Factory());
        deserializer.deserialize(object, data);
    }

    public static byte[] hash(final byte[]... inputByteArrays) {
        return hash(null, inputByteArrays);
    }

    public static byte[] hash(final String inputString, final byte[]... inputByteArrays) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            if (inputString != null) {
                md.update(inputString.getBytes(StandardCharsets.UTF_8));
            }
            for (byte[] input : inputByteArrays) md.update(input);
            return md.digest();
        } catch (NoSuchAlgorithmException exc) {
            throw new RuntimeException(exc);
        }
    }

    public static byte[] aeadEncrypt(final byte[] plaintext, final byte[] associatedData, final byte[] key,
                                     final boolean includeAd) {
        Preconditions.checkArgument(key.length > 0, "key must not be empty");

        final byte[] trueKey = hash("key", key);
        final byte[] iv = hash("iv", key);
        try {
            // From https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final SecretKeySpec keySpec = new SecretKeySpec(trueKey, "AES");

            final GCMParameterSpec parameterSpec = new GCMParameterSpec(8 * Constants.KEY_SIZE_BYTES, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);
            cipher.updateAAD(associatedData);

            final byte[] c = cipher.doFinal(plaintext);

            if (includeAd) {
                return serialize(new AeadMessage(ByteBuffer.wrap(c), ByteBuffer.wrap(associatedData)));
            } else return c;
        } catch (GeneralSecurityException exc) {
            throw new RuntimeException(exc);
        }

    }

    /**
     * Returns null if it does not decrypt / MAC is wrong.
     **/
    public static byte[] aeadDecrypt(final byte[] ciphertext, final byte[] key) {
        final AeadMessage aead = new AeadMessage();
        try {
            deserialize(aead, ciphertext);
        } catch (TException exc) {
            return null;
        }
        return aeadDecrypt(aead.getC(), key, aead.getA());
    }

    public static byte[] aeadDecrypt(final byte[] ciphertext, final byte[] key, final byte[] associatedData) {
        Preconditions.checkArgument(key.length > 0, "key must not be empty");

        final byte[] trueKey = hash("key", key);
        final byte[] iv = hash("iv", key);
        try {
            // From https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(trueKey, "AES");

            final GCMParameterSpec parameterSpec = new GCMParameterSpec(8 * Constants.KEY_SIZE_BYTES, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);
            cipher.updateAAD(associatedData);

            try {
                return cipher.doFinal(ciphertext);
            } catch (AEADBadTagException exc) {
                return null;
            }
        } catch (GeneralSecurityException exc) {
            throw new RuntimeException(exc);
        }
    }

    /**
     * Returns null if it is not formatted properly.
     **/
    public static byte[] aeadGetAD(final byte[] encrypted) {
        final AeadMessage aead = new AeadMessage();
        try {
            deserialize(aead, encrypted);
        } catch (TException exc) {
            return null;
        }
        return aead.getA();
    }

    /**
     * Copies an array from source to dest ensuring that destination has the same length as source
     */
    public static void copy(final byte[] source, final byte[] dest) {
        Preconditions.checkArgument(source.length == dest.length, "source and dest must be of same length");
        System.arraycopy(source, 0, dest, 0, source.length);
    }

    public static byte[] asArray(ByteBuffer buffer) {
        byte[] asArray = new byte[buffer.remaining()];
        buffer.mark();
        buffer.get(asArray);
        buffer.reset();
        return asArray;
    }

    public static byte[] concat(final byte[]... inputByteArrays) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (byte[] input : inputByteArrays) out.write(input);
            return out.toByteArray();
        } catch (IOException exc) {
            return null;
        }
    }

    /**
     * Adds the key-value pair (key, value) to the given persistent map, treated as a multi-valued
     * map.
     */
    public static <K, V> HashPMap<K, TreePVector<V>> putMulti(HashPMap<K, TreePVector<V>> map, K key, V value) {
        TreePVector<V> vector = map.get(key);
        if (vector == null) vector = TreePVector.empty();
        vector = vector.plus(value);
        return map.plus(key, vector);
    }
}
