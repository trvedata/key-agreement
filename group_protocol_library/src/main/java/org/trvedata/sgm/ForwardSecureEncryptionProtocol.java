package org.trvedata.sgm;

import org.trvedata.sgm.misc.ByteHolder;
import org.trvedata.sgm.misc.Constants;
import org.trvedata.sgm.misc.Utils;

/**
 * A {@link ForwardSecureEncryptionProtocol} ("Forward-Secure Authenticated Encryption") protocol is the interface used
 * by {@link ModularDsgm} to handle symmetric-key encryption and decryption of application messages.  It is based on the
 * interface of the Forward-Secure AEAD scheme described in section 4.2 of "The Double Ratchet: Security Notions,
 * Proofs, and Modularization for the Signal Protocol" by Alwen, Coretti, and Dodis (<a
 * href="https://eprint.iacr.org/2018/1037">https://eprint.iacr.org/2018/1037</a>), with the difference that we exclude
 * associated data, because we have no need for it.  An implementation is considered secure if it satisfies the security
 * properties described in that paper.
 * <p>
 * {@link ForwardSecureEncryptionProtocol} objects should be immutable.  "Mutating" methods must return a new {@link
 * ForwardSecureEncryptionProtocol} while leaving the original unchanged.
 * <p>
 * An instance of this class can assume that it will be used only for encryption or only for decryption.
 */
public interface ForwardSecureEncryptionProtocol<S extends ForwardSecureEncryptionProtocol.State> {

    /**
     * Encrypt a given plaintext under the next message encryption key.  Typically this will also ratchet the message
     * encryption key forward, for forward secrecy.  This method corresponds to FS-Send in the paper, but without
     * associated data.
     *
     * @param state     The state to reference (immutably).
     * @param plaintext The plaintext message
     * @return (updated state, the encryption of { @ code plaintext } possibly with metadata describing which message
     *encryption key was used).
     */
    EncryptionResult<S> encrypt(final S state, final byte[] plaintext);

    /**
     * Decrypt a given ciphertext under the message encryption key specified by its metadata. Typically this will also
     * ratchet the message decryption key forward and securely delete any used keys, for forward secrecy. Ciphertexts
     * will be delivered in an order enforced by the {@link ModularDsgm}'s {@link Orderer}, and in particular, they may
     * be delivered out-of-order if the {@link Orderer} allows it.
     *
     * @param state      The state to reference (immutably).
     * @param ciphertext The ciphertext, output by the {@link ForwardSecureEncryptionProtocol#encrypt} method of another
     *                   group member's {@link ForwardSecureEncryptionProtocol} object initialized with the same {@code
     *                   key}.
     * @return (updated state, the decrypted plaintext or { @ code null } if decryption failed).
     */
    DecryptionResult<S> decrypt(final S state, final byte[] ciphertext);

    /**
     * Return a {@link ForwardSecureEncryptionProtocol.State} initialized with the given {@code key}. This corresponds
     * to FS-Init-S and FS-Init-R in the paper.
     *
     * @param key A symmetric key of {@link Constants#KEY_SIZE_BYTES} length.
     * @return The {@link ForwardSecureEncryptionProtocol.State}.
     */
    S init(Key key);

    class Key extends ByteHolder {
        public Key(final byte[] bytes) {
            super(bytes);
        }

        public static Key of(final byte[] bytes) {
            return new Key(bytes);
        }

        public static Key random() {
            return new Key(Utils.getSecureRandomBytes(Constants.KEY_SIZE_BYTES));
        }
    }

    interface State {
    }

    class EncryptionResult<S extends State> {
        final S state;
        final byte[] ciphertext;

        public EncryptionResult(final S state, final byte[] ciphertext) {
            this.state = state;
            this.ciphertext = ciphertext;
        }
    }

    class DecryptionResult<S extends State> {
        final S state;
        final byte[] plaintext;

        public DecryptionResult(final S state, final byte[] plaintext) {
            this.state = state;
            this.plaintext = plaintext;
        }
    }
}
