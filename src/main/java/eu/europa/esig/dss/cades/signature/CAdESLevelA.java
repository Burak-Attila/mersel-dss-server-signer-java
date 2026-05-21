package eu.europa.esig.dss.cades.signature;

import java.security.MessageDigest;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.esf.ESFAttributes;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SigningMaterial;

/**
 * CAdES-A (ESA) seviyesinde {@code archive-time-stamp-v2} unsigned attribute'u
 * ekler (ETSI TS 101 733 §6.4.1). Önce {@link CAdESLevelXL#extend} ile X-Long
 * uzantıları eklenir; ardından sonuç DER-kanonik biçime alınır, ATSv2 mesaj
 * imprinti hesaplanır, TSA'dan zaman damgası alınır ve CMS'in unsigned
 * attribute setine eklenir.
 *
 * <p><b>Önemli</b>: DSS 6.3'ün {@code CAdES_BASELINE_LTA} seviyesi yalnızca
 * {@code archive-time-stamp-v3} üretebiliyor; ancak Türk KamuSM / TÜBİTAK
 * ESYA doğrulayıcısı yalnızca v2 formatını tanıyor. Bu sınıf v2'yi BC ile
 * elle ekler, v3 hiçbir zaman üretilmez.</p>
 *
 * @see CAdESLevelXL
 * @see CadesUtil#computeArchiveTimestampV2MessageImprint(CMSSignedData)
 */
public class CAdESLevelA extends CAdESLevelXL {

    private static final Logger LOGGER = LoggerFactory.getLogger(CAdESLevelA.class);

    public CAdESLevelA(CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
    }

    /**
     * Baseline-LT çıktısına X-Long uzantılarını ve {@code archive-time-stamp-v2}'yi ekler.
     *
     * @param signedData      DSS baseline-LT çıktısı (CMS)
     * @param material        imzalama materyali (zincir + private key)
     * @param digestAlgorithm imzanın özet algoritması (ATSv2 hash'i de bu algoritmayla)
     * @param tspSource       arşiv damgasını alacak TSA kaynağı
     */
    public CMSSignedData extend(CMSSignedData signedData,
                                SigningMaterial material,
                                DigestAlgorithm digestAlgorithm,
                                TSPSource tspSource) {
        try {
            CMSSignedData xLong = super.extend(signedData, material, digestAlgorithm);

            // DER round-trip: ATSv2 hash'ini wire byte'ları üzerinden hesaplamak
            // için CMS'i kendi DER kodlamasına bir kez parse edip geri okuyoruz.
            // Böylece ASN.1 SET'leri DER-sıralı hale geliyor; doğrulayıcı ile hash
            // uyumsuzluğu olmuyor.
            CMSSignedData xLongDer = new CMSSignedData(xLong.getEncoded(ASN1Encoding.DER));

            byte[] messageImprintInput =
                    CadesUtil.computeArchiveTimestampV2MessageImprint(xLongDer);
            byte[] digest = MessageDigest.getInstance(digestAlgorithm.getJavaName())
                    .digest(messageImprintInput);

            TimestampBinary tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digest);
            TimeStampToken tsToken = new TimeStampToken(
                    ContentInfo.getInstance(ASN1Sequence.getInstance(tsBinary.getBytes())));

            Attribute atsV2 = new Attribute(
                    ESFAttributes.archiveTimestampV2,
                    new DERSet(tsToken.toCMSSignedData().toASN1Structure()));

            CMSSignedData esa = CadesUtil.appendUnsignedAttribute(xLongDer, atsV2);
            LOGGER.info("CAdES-ESA (archive-time-stamp-v2) eklendi.");
            return esa;
        } catch (SignatureException e) {
            throw e;
        } catch (Exception ex) {
            throw new SignatureException("CADES_ESA_EXT_ERROR",
                    "CAdES-ESA (archive-time-stamp-v2) uzantısı eklenemedi", ex);
        }
    }
}
