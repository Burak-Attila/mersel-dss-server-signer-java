package io.mersel.dss.signer.api.models.enums;

/**
 * CAdES imza seviyeleri. {@link io.mersel.dss.signer.api.dtos.SignCadesDto#getLevel()}
 * üzerinden gelen string değer {@link #fromString(String)} ile bu enum'a çözülür.
 *
 * <ul>
 *   <li>{@link #BES} — ETSI EN 319 122-1 CAdES-BASELINE-B (varsayılan).</li>
 *   <li>{@link #T} — BES + RFC 3161 imza zaman damgası (CAdES-BASELINE-T).</li>
 *   <li>{@link #X_LONG} — CAdES-X-Long: T'ye ek olarak {@code cert-refs},
 *       {@code revoc-refs}, {@code cert-values}, {@code revoc-values} unsigned
 *       attribute'ları imza zarfına eklenir.</li>
 *   <li>{@link #ESA} — CAdES-A (ETSI Archive Signature): X-Long üstüne
 *       {@code archive-time-stamp-v2} eklenir. v3 üretilmez (Türk KamuSM/TÜBİTAK
 *       ESYA doğrulayıcısı yalnızca v2'yi tanır).</li>
 * </ul>
 */
public enum CadesSignatureLevel {

    BES,
    T,
    X_LONG,
    ESA;

    /**
     * Bu seviye RFC 3161 zaman damgası (TSA) gerektiriyor mu?
     */
    public boolean requiresTimestamp() {
        return this != BES;
    }

    /**
     * Kullanıcıdan gelen string'i enum'a çevirir. Büyük/küçük harf duyarsızdır;
     * tire ({@code -}) ve altçizgi ({@code _}) birbirinin yerine kullanılabilir.
     * {@code null} veya boş değer için {@link #BES} döner.
     *
     * @param raw kullanıcı girdisi (ör. "x-long", "X_LONG", "XLong", "ESA")
     * @return karşılık gelen enum
     * @throws IllegalArgumentException tanınmayan değer için
     */
    public static CadesSignatureLevel fromString(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return BES;
        }
        String normalized = raw.trim().toUpperCase().replace('-', '_');
        switch (normalized) {
            case "BES":
            case "BASELINE_B":
                return BES;
            case "T":
            case "BASELINE_T":
                return T;
            case "X_LONG":
            case "XLONG":
            case "X":
                return X_LONG;
            case "ESA":
            case "A":
            case "BASELINE_LTA":
                return ESA;
            default:
                throw new IllegalArgumentException(
                        "Bilinmeyen CAdES seviyesi: " + raw +
                                ". Desteklenen: BES, T, X-LONG, ESA");
        }
    }
}
