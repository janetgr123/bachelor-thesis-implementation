package ch.bt.model.multimap;

import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * This class encapsulates a ciphertext with its iv used during encryption with a symmetric
 * encryption scheme
 *
 * @author Janet Greutmann
 */
public final class CiphertextWithIV extends Ciphertext implements Comparable<CiphertextWithIV> {
    /** the iv */
    private final byte[] iv;

    /** the encrypted data */
    private final byte[] data;

    public CiphertextWithIV(byte[] iv, byte[] data) {
        this.iv = iv;
        this.data = data;
    }

    /**
     * Generated method
     *
     * @param o the object that should be tested for equality to this
     * @return true is the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        CiphertextWithIV that = (CiphertextWithIV) o;

        return new EqualsBuilder().append(iv, that.iv).append(data, that.data).isEquals();
    }

    /**
     * Generated method
     *
     * @return the hash code of this
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(iv).append(data).toHashCode();
    }

    /**
     * Generated method
     *
     * @param ciphertextWithIV the ciphertext that should be compared to this
     * @return negative number if this &lt; ciphertextWithIV, 0 for equality and positive number if
     *     this &gt; ciphertextWithIV
     */
    @Override
    public int compareTo(CiphertextWithIV ciphertextWithIV) {
        return new CompareToBuilder()
                .append(this.iv, ciphertextWithIV.iv)
                .append(this.data, ciphertextWithIV.data)
                .toComparison();
    }

    /**
     * Generated method
     *
     * @return the data of this in string format
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this).append("iv", iv).append("data", data).toString();
    }

    /**
     * Getter for the iv
     *
     * @return the iv
     */
    public byte[] iv() {
        return iv;
    }

    /**
     * Getter for the encrypted data
     *
     * @return the encrypted data
     */
    public byte[] data() {
        return data;
    }
}
