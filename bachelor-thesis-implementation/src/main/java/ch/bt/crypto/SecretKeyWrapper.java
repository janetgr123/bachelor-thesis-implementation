package ch.bt.crypto;
import java.util.List;

public class SecretKeyWrapper {
    private List<SecretKeySingle> keys;

    public SecretKeyWrapper(final List<SecretKeySingle> keys){
        this.keys = keys;
    }

    public List<SecretKeySingle> getKeys(){
        return this.keys;
    }

}
