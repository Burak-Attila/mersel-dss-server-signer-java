package eu.europa.esig.dss.cades.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.esf.ESFAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;

/**
 * CAdES seviye uzantılarının paylaştığı yardımcı işlemler.
 *
 * <p>Buradaki metodlar, {@link CAdESLevelC}, {@link CAdESLevelXL} ve
 * {@link CAdESLevelA} arasında ortak ihtiyaçları karşılar:</p>
 * <ul>
 *   <li>BC ASN.1 yapı kurucuları (IssuerSerial, fingerprint, CRL Number).</li>
 *   <li>Unsigned attribute tablo birleştirme / ekleme.</li>
 *   <li>İmzadaki TSA token'larından sertifika çıkartma.</li>
 *   <li>DSS {@link CMSDocumentAnalyzer} üzerinden imza zarfı için CRL/OCSP toplama
 *       (XAdES'in {@code XAdESLevelC} ile aynı pattern).</li>
 *   <li>{@code archive-time-stamp-v2} mesaj imprintinin ETSI TS 101 733 §6.4.2'ye
 *       göre hesaplanması.</li>
 * </ul>
 *
 * <p>Türk KamuSM / TÜBİTAK ESYA doğrulayıcısı ile uyumluluk için yapılan
 * davranışsal seçimler (DER round-trip, root cert dahil etme kuralları,
 * v3 dışlama, BER mode encapContentInfo) burada korunur.</p>
 */
final class CadesUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(CadesUtil.class);

    /** ETSI TS 101 733 {@code archive-time-stamp-v3} OID — ATSv2 hash girdisinde dışlanır. */
    static final ASN1ObjectIdentifier ID_AA_ETS_ARCHIVE_TIMESTAMP_V3 =
            new ASN1ObjectIdentifier("0.4.0.1733.2.4");

    private CadesUtil() {
    }

    // ---------------------------------------------------------------------
    // BouncyCastle helpers
    // ---------------------------------------------------------------------

    static IssuerSerial buildIssuerSerial(X509Certificate cert) {
        X500Name issuer = X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
        GeneralName generalName = new GeneralName(issuer);
        GeneralNames generalNames = new GeneralNames(generalName);
        return new IssuerSerial(generalNames, cert.getSerialNumber());
    }

    static String fingerprint(byte[] encoded) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] d = sha.digest(encoded);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception ex) {
            return new String(encoded, java.nio.charset.StandardCharsets.ISO_8859_1);
        }
    }

    static String certKey(X509Certificate cert) {
        try {
            return fingerprint(cert.getEncoded());
        } catch (Exception ex) {
            return cert.getSubjectX500Principal().getName() + "|" + cert.getSerialNumber();
        }
    }

    /** Self-signed (subject == issuer) ise {@code true} döner. */
    static boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }

    /**
     * CRL'in "CRL Number" extension değerini (OID 2.5.29.20) okur. Extension
     * yoksa {@code null} döner. ESYA doğrulayıcısı CRL referansını CRL değeri
     * ile eşleştirmek için crlNumber'ı kullanıyor; yoksa referans paneli boş
     * kalıyor (ETSI TS 101 733 6.2.2 OPTIONAL ama ESYA arıyor).
     */
    static java.math.BigInteger extractCrlNumber(X509CRL crl) {
        byte[] extBytes = crl.getExtensionValue("2.5.29.20");
        if (extBytes == null) {
            return null;
        }
        try {
            ASN1OctetString wrapped = ASN1OctetString.getInstance(extBytes);
            ASN1Integer crlNum = ASN1Integer.getInstance(wrapped.getOctets());
            return crlNum.getValue();
        } catch (Exception ex) {
            LOGGER.debug("CRL Number extension parse edilemedi: {}", ex.getMessage());
            return null;
        }
    }

    // ---------------------------------------------------------------------
    // Unsigned attribute helpers
    // ---------------------------------------------------------------------

    /** Var olan unsigned attribute tablosuna verilen tüm attribute'ları ekler. */
    static CMSSignedData mergeUnsignedAttributes(CMSSignedData signedData, AttributeTable toMerge) {
        List<SignerInformation> newSigners = new ArrayList<>();
        for (Object o : signedData.getSignerInfos().getSigners()) {
            SignerInformation si = (SignerInformation) o;
            AttributeTable unsigned = si.getUnsignedAttributes();
            if (unsigned == null) {
                unsigned = new AttributeTable(new Hashtable<>());
            }
            Enumeration<?> keys = toMerge.toHashtable().keys();
            while (keys.hasMoreElements()) {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) keys.nextElement();
                Attribute attr = toMerge.get(oid);
                unsigned = unsigned.remove(oid);
                unsigned = unsigned.add(oid, attr.getAttrValues().getObjectAt(0));
            }
            newSigners.add(SignerInformation.replaceUnsignedAttributes(si, unsigned));
        }
        return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
    }

    /** Var olan tabloya tek bir attribute'u sona ekler (archive-time-stamp-v2 için). */
    static CMSSignedData appendUnsignedAttribute(CMSSignedData signedData, Attribute attribute) {
        List<SignerInformation> newSigners = new ArrayList<>();
        for (Object o : signedData.getSignerInfos().getSigners()) {
            SignerInformation si = (SignerInformation) o;
            AttributeTable unsigned = si.getUnsignedAttributes();
            if (unsigned == null) {
                unsigned = new AttributeTable(new Hashtable<>());
            }
            unsigned = unsigned.add(attribute.getAttrType(),
                    attribute.getAttrValues().getObjectAt(0));
            newSigners.add(SignerInformation.replaceUnsignedAttributes(si, unsigned));
        }
        return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
    }

    // ---------------------------------------------------------------------
    // TSA certificate extraction from existing timestamp tokens
    // ---------------------------------------------------------------------

    /**
     * CMS'in SignerInfo'larındaki {@code signatureTimeStampToken} ve (varsa)
     * {@code archiveTimestampV2} unsigned attribute'larına gömülü TSA
     * sertifikalarını çıkarır. Sertifikalar SHA-256 özetiyle dedup'lanır.
     */
    static Set<CertificateToken> extractTimestampCerts(CMSSignedData signedData) {
        Set<CertificateToken> result = new LinkedHashSet<>();
        Set<String> seen = new HashSet<>();
        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (Exception ex) {
            LOGGER.warn("CertificateFactory yüklenemedi", ex);
            return result;
        }

        for (Object o : signedData.getSignerInfos().getSigners()) {
            SignerInformation si = (SignerInformation) o;
            AttributeTable unsigned = si.getUnsignedAttributes();
            if (unsigned == null) {
                continue;
            }
            addCertsFromTimestampAttribute(unsigned.get(
                    PKCSObjectIdentifiers.id_aa_signatureTimeStampToken),
                    certFactory, result, seen);
            addCertsFromTimestampAttribute(unsigned.get(
                    ESFAttributes.archiveTimestampV2),
                    certFactory, result, seen);
        }
        return result;
    }

    private static void addCertsFromTimestampAttribute(Attribute attr,
                                                       CertificateFactory certFactory,
                                                       Set<CertificateToken> out,
                                                       Set<String> seen) {
        if (attr == null) {
            return;
        }
        ASN1Set values = attr.getAttrValues();
        for (int i = 0; i < values.size(); i++) {
            try {
                ContentInfo tsContent = ContentInfo.getInstance(values.getObjectAt(i));
                TimeStampToken token = new TimeStampToken(tsContent);
                Store<X509CertificateHolder> store = token.getCertificates();
                if (store == null) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                Collection<X509CertificateHolder> holders = store.getMatches(null);
                for (X509CertificateHolder holder : holders) {
                    byte[] encoded = holder.getEncoded();
                    String key = fingerprint(encoded);
                    if (!seen.add(key)) {
                        continue;
                    }
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                            new ByteArrayInputStream(encoded));
                    out.add(new CertificateToken(cert));
                }
            } catch (Exception ex) {
                LOGGER.warn("Zaman damgasındaki sertifikalar çıkarılamadı: {}", ex.getMessage());
            }
        }
    }

    // ---------------------------------------------------------------------
    // DSS-native revocation collection (XAdESLevelC ile aynı pattern)
    // ---------------------------------------------------------------------

    /**
     * X-Long / ESA çıktısında imzaya gömülecek revocation verisi.
     * {@link X509CRL} ve {@link BasicOCSPResp} olarak tutulur — BC level
     * builder'ları bu tipleri bekliyor.
     */
    static final class CadesRevocationData {
        private final List<X509CRL> crls;
        private final List<BasicOCSPResp> ocsps;

        CadesRevocationData(List<X509CRL> crls, List<BasicOCSPResp> ocsps) {
            this.crls = crls;
            this.ocsps = ocsps;
        }

        List<X509CRL> getCrls() { return crls; }
        List<BasicOCSPResp> getOcsps() { return ocsps; }
        boolean isEmpty() { return crls.isEmpty() && ocsps.isEmpty(); }
    }

    /**
     * DSS {@link CMSDocumentAnalyzer} üzerinden imza için CRL/OCSP toplar.
     *
     * <p>XAdES'in {@code XAdESLevelC} extension'ı ile birebir aynı pattern:
     * analyzer'ı {@link CertificateVerifier}'a bağla, signature timestamp
     * tokenlarını temizle (ki TSA cert revocation refs/values'a girmesin —
     * MA3 referans çıktısıyla uyumlu), validation data'yı çek, signer chain
     * için topladığı CRL/OCSP tokenlarını BC tipleriyle döndür.</p>
     *
     * <p>{@link CertificateVerifier#getCrlSource()} ve
     * {@link CertificateVerifier#getOcspSource()} ile yapılandırılmış
     * {@code OnlineCRLSource} / {@code OnlineOCSPSource} kullanılır; ağ hatası
     * yapılması durumunda DSS log yazar ve token'ı atlar, exception fırlatmaz.</p>
     */
    static CadesRevocationData collectRevocation(CMSSignedData cmsSigned,
                                                 CertificateVerifier verifier) throws Exception {
        CMSDocumentAnalyzer analyzer = new CMSDocumentAnalyzer(cmsSigned);
        analyzer.setCertificateVerifier(verifier);

        List<AdvancedSignature> signatures = analyzer.getSignatures();
        if (signatures.isEmpty()) {
            return new CadesRevocationData(Collections.emptyList(), Collections.emptyList());
        }

        // XAdESLevelC ile aynı davranış: signer chain dışındaki (TSA) revocation
        // bu adımda toplanmasın diye signature timestamp tokenlarını temizliyoruz.
        for (AdvancedSignature s : signatures) {
            s.getSignatureTimestamps().clear();
        }

        ValidationDataContainer vdc = analyzer.getValidationData(signatures);

        List<X509CRL> crls = new ArrayList<>();
        List<BasicOCSPResp> ocsps = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        for (AdvancedSignature s : signatures) {
            ValidationData vd = vdc.getAllValidationDataForSignature(s);
            for (CRLToken t : vd.getCrlTokens()) {
                crls.add((X509CRL) cf.generateCRL(new ByteArrayInputStream(t.getEncoded())));
            }
            for (OCSPToken t : vd.getOcspTokens()) {
                ocsps.add(t.getBasicOCSPResp());
            }
        }

        return new CadesRevocationData(crls, ocsps);
    }

    // ---------------------------------------------------------------------
    // archive-time-stamp-v2 message imprint
    // ---------------------------------------------------------------------

    /**
     * ETSI TS 101 733 §6.4.2 uyarınca {@code archive-time-stamp-v2} mesaj imprintini
     * oluşturur. Hash girdisi aşağıdaki DER-kodlu alanların ardışık birleşimidir:
     * <ol>
     *   <li>encapContentInfo (DER; içerik {@link BEROctetString} ise BER kodlaması)</li>
     *   <li>certificates {@code [0] IMPLICIT} (varsa, tag 0xa0 — SEQUENCE sarması
     *       ile orijinal sıra korunur)</li>
     *   <li>crls {@code [1] IMPLICIT} (varsa, tag 0xa1 — aynı şekilde SEQUENCE)</li>
     *   <li>Her SignerInfo için alanlar <b>teker teker</b> (dış SEQUENCE zarfı
     *       olmadan): version, SID, digestAlgorithm, {@code [0] IMPLICIT} signedAttrs,
     *       digestEncryptionAlgorithm, encryptedDigest, {@code [1] IMPLICIT}
     *       unsignedAttrs (mevcut ATSv2/v3 hariç).</li>
     * </ol>
     *
     * <p>Yaklaşım, DSS 6.3'ün {@code CAdESTimestampMessageDigestBuilder}'ı ile aynı
     * şekildedir; bu sayede Türk KamuSM / E-GÜVEN doğrulayıcılarının beklediği
     * byte dizisi üretilmiş olur.</p>
     */
    static byte[] computeArchiveTimestampV2MessageImprint(CMSSignedData signedData)
            throws IOException {
        ContentInfo contentInfo = signedData.toASN1Structure();
        SignedData sd = SignedData.getInstance(contentInfo.getContent());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        ContentInfo encap = sd.getEncapContentInfo();
        if (encap.getContent() instanceof BEROctetString) {
            baos.write(encap.getEncoded(ASN1Encoding.BER));
        } else {
            baos.write(encap.getEncoded(ASN1Encoding.DER));
        }

        ASN1Set certs = sd.getCertificates();
        if (certs != null) {
            byte[] certsEnc = new DERTaggedObject(false, 0,
                    new DERSequence(certs.toArray())).getEncoded(ASN1Encoding.DER);
            baos.write(certsEnc);
        }

        ASN1Set crls = sd.getCRLs();
        if (crls != null) {
            byte[] crlsEnc = new DERTaggedObject(false, 1,
                    new DERSequence(crls.toArray())).getEncoded(ASN1Encoding.DER);
            baos.write(crlsEnc);
        }

        for (Object o : signedData.getSignerInfos().getSigners()) {
            SignerInformation si = (SignerInformation) o;
            writeSignerInfoFields(baos, si);
        }

        return baos.toByteArray();
    }

    private static void writeSignerInfoFields(ByteArrayOutputStream baos, SignerInformation si)
            throws IOException {
        SignerInfo signerInfo = si.toASN1Structure();

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(signerInfo.getVersion());
        v.add(signerInfo.getSID());
        v.add(signerInfo.getDigestAlgorithm());

        byte[] signedAttrsBytes = si.getEncodedSignedAttributes();
        if (signedAttrsBytes != null) {
            ASN1Set signedAttrsSet = (ASN1Set) ASN1Primitive.fromByteArray(signedAttrsBytes);
            v.add(new DERTaggedObject(false, 0, signedAttrsSet));
        }

        v.add(signerInfo.getDigestEncryptionAlgorithm());
        v.add(signerInfo.getEncryptedDigest());

        ASN1Set unsignedAttrs = signerInfo.getUnauthenticatedAttributes();
        if (unsignedAttrs != null) {
            ASN1Sequence filtered = filterUnsignedAttributes(unsignedAttrs);
            if (filtered != null && filtered.size() > 0) {
                v.add(new DERTaggedObject(false, 1, filtered));
            }
        }

        DERSequence holder = new DERSequence(v);
        for (int i = 0; i < holder.size(); i++) {
            baos.write(holder.getObjectAt(i).toASN1Primitive().getEncoded(ASN1Encoding.DER));
        }
    }

    private static ASN1Sequence filterUnsignedAttributes(ASN1Set unsignedAttrs) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < unsignedAttrs.size(); i++) {
            Attribute attr = Attribute.getInstance(unsignedAttrs.getObjectAt(i));
            ASN1ObjectIdentifier oid = attr.getAttrType();
            if (ESFAttributes.archiveTimestampV2.equals(oid)) {
                continue;
            }
            if (ID_AA_ETS_ARCHIVE_TIMESTAMP_V3.equals(oid)) {
                continue;
            }
            v.add(attr);
        }
        return new DERSequence(v);
    }
}
