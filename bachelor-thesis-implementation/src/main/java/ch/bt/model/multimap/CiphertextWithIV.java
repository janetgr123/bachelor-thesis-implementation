package ch.bt.model.multimap;

import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

public final class CiphertextWithIV extends Ciphertext implements Comparable<CiphertextWithIV> {
    private final byte[] iv;
    private final byte[] data;

    public CiphertextWithIV(byte[] iv, byte[] data) {
        this.iv = iv;
        this.data = data;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        CiphertextWithIV that = (CiphertextWithIV) o;

        return new EqualsBuilder().append(iv, that.iv).append(data, that.data).isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(iv).append(data).toHashCode();
    }

    public byte[] iv() {
        return iv;
    }

    public byte[] data() {
        return data;
    }

    @Override
    public int compareTo(CiphertextWithIV ciphertextWithIV) {
        return new CompareToBuilder()
                .append(this.iv, ciphertextWithIV.iv)
                .append(this.data, ciphertextWithIV.data)
                .toComparison();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("iv", iv).append("data", data).toString();
    }
}
