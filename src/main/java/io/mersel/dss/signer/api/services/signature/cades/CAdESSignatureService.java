package io.mersel.dss.signer.api.services.signature.cades;

import java.io.InputStream;
import java.util.Base64;
import java.util.concurrent.Semaphore;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESLevelA;
import eu.europa.esig.dss.cades.signature.CAdESLevelXL;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.CadesSignatureLevel;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import io.mersel.dss.signer.api.services.crypto.DigestAlgorithmResolverService;
import io.mersel.dss.signer.api.services.timestamp.TimestampConfigurationService;

/**
 * CAdES elektronik imzalarını üreten servis.
 *
 * <p>Desteklenen seviyeler ({@link CadesSignatureLevel}):</p>
 * <ul>
 *   <li><b>BES</b> — ETSI EN 319 122-1 {@code CAdES-BASELINE-B}. PAdES V2 ile aynı
 *       yaklaşımda {@code SigningCertificateV2} attribute barındıran CMS zarfı.</li>
 *   <li><b>T</b> — BES + RFC 3161 imza zaman damgası.</li>
 *   <li><b>X-LONG</b> — CAdES-X-Long (ETSI TS 101 733). T seviyesine ek olarak
 *       {@code complete-certificate-references}, {@code complete-revocation-references},
 *       {@code certificate-values} ve {@code revocation-values} unsigned attribute'ları
 *       eklenir; CRL ve OCSP değerleri imzanın içine yazılır.</li>
 *   <li><b>ESA</b> — ETSI TS 101 733 CAdES-A: X-Long + {@code archive-time-stamp-v2}.
 *       <b>Kesinlikle v3 dahil edilmez</b>; Türk KamuSM / TÜBİTAK ESYA doğrulayıcısı
 *       yalnızca v2 formatını tanır.</li>
 * </ul>
 *
 * <p>X-Long ve ESA seviyeleri DSS'in baseline çıktısını post-process ederek
 * oluşturulur. Post-processing, XAdES override hierarşisi ile aynı stilde
 * {@code eu.europa.esig.dss.cades.signature} paketi altındaki seviye
 * sınıflarına bölünmüştür: {@link CAdESLevelXL} (refs + values),
 * {@link CAdESLevelA} (XL + archive-time-stamp-v2).</p>
 *
 * <h3>Eşzamanlılık</h3>
 * <p>PKCS#11 (HSM) session havuzlarının tükenmesini engellemek için eş zamanlı imza
 * sayısı bir {@link Semaphore} ile sınırlandırılır.</p>
 *
 * @see CAdESService
 * @see CAdESLevelXL
 * @see CAdESLevelA
 * @see CadesRevocationCollector
 * @see TimestampConfigurationService
 */
@Service
public class CAdESSignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CAdESSignatureService.class);

    private final CAdESService cadesService;
    private final CryptoSignerService cryptoSigner;
    private final DigestAlgorithmResolverService digestAlgorithmResolver;
    private final TimestampConfigurationService timestampConfigurationService;
    private final CertificateVerifier certificateVerifier;
    private final Semaphore semaphore;

    public CAdESSignatureService(CAdESService cadesService,
                                 CryptoSignerService cryptoSigner,
                                 DigestAlgorithmResolverService digestAlgorithmResolver,
                                 TimestampConfigurationService timestampConfigurationService,
                                 CertificateVerifier certificateVerifier,
                                 Semaphore signatureSemaphore) {
        this.cadesService = cadesService;
        this.cryptoSigner = cryptoSigner;
        this.digestAlgorithmResolver = digestAlgorithmResolver;
        this.timestampConfigurationService = timestampConfigurationService;
        this.certificateVerifier = certificateVerifier;
        this.semaphore = signatureSemaphore;
    }


    public SignResponse signData(InputStream dataInputStream,
                                 boolean detached,
                                 SigningMaterial material) {
        return signData(dataInputStream, detached, CadesSignatureLevel.BES, material);
    }

    /**
     * Verilen stream'deki veriyi talep edilen seviyede imzalar.
     *
     * @param dataInputStream imzalanacak dosyanın stream'i — metot içinde tüketilir, kapatılmaz
     * @param detached        {@code true} → ayrık imza, {@code false} → gömülü imza
     * @param level           üretilecek CAdES seviyesi; {@code null} → {@link CadesSignatureLevel#BES}
     * @param material        sertifika zinciri ve private key'i barındıran imzalama materyali
     * @return imzalanmış byte dizisi ve Base64 kodlanmış imza değerini içeren {@link SignResponse}
     * @throws SignatureException imza oluşturma sırasında herhangi bir hata meydana gelirse
     */
    public SignResponse signData(InputStream dataInputStream,
                                 boolean detached,
                                 CadesSignatureLevel level,
                                 SigningMaterial material) {
        CadesSignatureLevel effectiveLevel = level != null ? level : CadesSignatureLevel.BES;
        try {
            byte[] contentBytes = IOUtils.toByteArray(dataInputStream);
            DSSDocument document = new InMemoryDocument(contentBytes, "document.bin");

            DigestAlgorithm digestAlgorithm =
                    digestAlgorithmResolver.resolveDigestAlgorithm(material.getSigningCertificate());

            configureTimestampSourceIfNeeded(effectiveLevel);

            // X-Long ve ESA için DSS tarafında daima T seviyesinde imzalıyoruz;
            SignatureLevel dssLevel = mapToDssLevel(effectiveLevel);
            CAdESSignatureParameters parameters =
                    buildParameters(detached, digestAlgorithm, dssLevel, effectiveLevel, material);

            byte[] signedBytes;
            String encodedSignature;

            semaphore.acquire();
            try {
                ToBeSigned dataToSign = cadesService.getDataToSign(document, parameters);
                SignatureValue signatureValue = cryptoSigner.sign(
                        dataToSign,
                        material,
                        digestAlgorithm);

                DSSDocument baselineDoc = cadesService.signDocument(document, parameters, signatureValue);
                byte[] baselineBytes = IOUtils.toByteArray(baselineDoc.openStream());

                signedBytes = applyLegacyExtensions(
                        baselineBytes, effectiveLevel, material, digestAlgorithm);
                encodedSignature = Base64.getEncoder().encodeToString(signatureValue.getValue());
            } finally {
                semaphore.release();
            }

            LOGGER.info("CAdES imzası başarıyla oluşturuldu (seviye: {}, detached: {})",
                    effectiveLevel, detached);
            return new SignResponse(signedBytes, encodedSignature);

        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error("CAdES imzası oluşturulurken hata (seviye: {})", effectiveLevel, e);
            throw new SignatureException("CADES_SIGN_ERROR",
                    "CAdES imzası oluşturulamadı (seviye: " + effectiveLevel + ")", e);
        }
    }

    /**
     * Kullanıcıdan gelen seviyeyi DSS'e iletilecek seviyeye eşler.
     * <ul>
     *   <li>BES → {@code BASELINE_B}</li>
     *   <li>T → {@code BASELINE_T}</li>
     *   <li>X-LONG / ESA → {@code BASELINE_LT}. DSS, CRL/OCSP'yi
     *       {@code SignedData.crls} alanına yazar ve sertifika zincirini
     *       {@code SignedData.certificates}'a koyar. Legacy ETSI TS 101 733
     *       unsigned attribute'ları (cert-refs / cert-values / revoc-refs /
     *       revoc-values) Türk ESYA doğrulayıcısının zincir görüntüsünü
     *       bozduğu için <b>üretilmiyor</b>.</li>
     *   <li>ESA için baseline-LT çıktısının üstüne post-process olarak
     *       {@code archive-time-stamp-v2} ekleniyor; DSS'in {@code BASELINE_LTA}
     *       seviyesi v3 üretiyor ve ESYA kabul etmiyor.</li>
     * </ul>
     */
    private SignatureLevel mapToDssLevel(CadesSignatureLevel level) {
        switch (level) {
            case BES:
                return SignatureLevel.CAdES_BASELINE_B;
            case T:
                return SignatureLevel.CAdES_BASELINE_T;
            case X_LONG:
            case ESA:
                return SignatureLevel.CAdES_BASELINE_LT;
            default:
                return SignatureLevel.CAdES_BASELINE_B;
        }
    }

    /**
     * Post-processing aşaması: X-Long için DSS baseline-LT çıktısına ETSI TS
     * 101 733 legacy unsigned attribute'larını (cert-refs, cert-values,
     * revoc-refs, revoc-values) ekler. ESA için ek olarak
     * {@code archive-time-stamp-v2} ekler. BES ve T için DSS çıktısı aynen döner.
     */
    private byte[] applyLegacyExtensions(byte[] baselineBytes,
                                         CadesSignatureLevel level,
                                         SigningMaterial material,
                                         DigestAlgorithm digestAlgorithm) throws Exception {
        if (level == CadesSignatureLevel.BES || level == CadesSignatureLevel.T) {
            return baselineBytes;
        }

        CMSSignedData baseline = new CMSSignedData(baselineBytes);

        if (level == CadesSignatureLevel.X_LONG) {
            CMSSignedData xLong = new CAdESLevelXL(certificateVerifier)
                    .extend(baseline, material, digestAlgorithm);
            return xLong.getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        }

        // ESA = X-Long + archive-time-stamp-v2
        CMSSignedData esa = new CAdESLevelA(certificateVerifier)
                .extend(baseline, material, digestAlgorithm,
                        timestampConfigurationService.getTspSource());
        return esa.getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
    }

    /**
     * T/X-Long/ESA seviyeleri için {@link CAdESService}'e TSP kaynağını bağlar.
     * BES seviyesinde zaman damgası gerekmediği için atlanır.
     */
    private void configureTimestampSourceIfNeeded(CadesSignatureLevel level) {
        if (!level.requiresTimestamp()) {
            return;
        }
        if (!timestampConfigurationService.isAvailable()) {
            throw new SignatureException("CADES_TSP_MISSING",
                    level + " seviyesi için timestamp (TSA) yapılandırması zorunlu. " +
                            "TS_SERVER_HOST property'sini ayarlayın.");
        }
        cadesService.setTspSource(timestampConfigurationService.getTspSource());
    }

    /**
     * DSS {@link CAdESSignatureParameters} nesnesini oluşturur.
     */
    private CAdESSignatureParameters buildParameters(boolean detached,
                                                     DigestAlgorithm digestAlgorithm,
                                                     SignatureLevel dssLevel,
                                                     CadesSignatureLevel userLevel,
                                                     SigningMaterial material) {
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(dssLevel);
        parameters.setSignaturePackaging(
                detached ? SignaturePackaging.DETACHED : SignaturePackaging.ENVELOPING);
        parameters.setDigestAlgorithm(digestAlgorithm);
        parameters.setSigningCertificate(material.getPrimaryCertificateToken());
        parameters.setCertificateChain(material.getCertificateTokens());
        parameters.setCheckCertificateRevocation(true);
        if (userLevel.requiresTimestamp()) {
            CAdESTimestampParameters tsParams = new CAdESTimestampParameters();
            tsParams.setDigestAlgorithm(digestAlgorithm);
            parameters.setSignatureTimestampParameters(tsParams);
            parameters.setContentTimestampParameters(tsParams);

        }

        return parameters;
    }
}
