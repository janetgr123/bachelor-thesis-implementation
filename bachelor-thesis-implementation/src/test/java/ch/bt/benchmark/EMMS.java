package ch.bt.benchmark;

import ch.bt.emm.EMM;
import ch.bt.emm.TwoRoundEMM;
import ch.bt.emm.basic.BasicEMM;
import ch.bt.emm.dpVolumeHiding.DifferentiallyPrivateVolumeHidingEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMM;
import ch.bt.emm.volumeHiding.VolumeHidingEMMOptimised;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.List;

/**
 * This class encapsulates the different EMMs used for the benchmarks
 *
 * @author Janet Greutmann
 */
public class EMMS {
    public static final List<EMM> basicEmms;
    public static final List<EMM> vhEmms;
    public static final List<EMM> vhOEmms;
    public static final List<TwoRoundEMM> twoRoundEMMS;

    static {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    static {
        try {
            basicEmms = List.of(new BasicEMM(EMMSettings.SECURITY_PARAMETER));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            vhEmms =
                    List.of(new VolumeHidingEMM(EMMSettings.SECURITY_PARAMETER, EMMSettings.ALPHA));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            vhOEmms =
                    List.of(
                            new VolumeHidingEMMOptimised(
                                    EMMSettings.SECURITY_PARAMETER, EMMSettings.ALPHA));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        try {
            twoRoundEMMS =
                    List.of(
                            new DifferentiallyPrivateVolumeHidingEMM(
                                    EMMSettings.SECURITY_PARAMETER,
                                    EMMSettings.EPSILON,
                                    EMMSettings.ALPHA));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
