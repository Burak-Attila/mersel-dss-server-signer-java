package eu.europa.esig.dss.cades.signature;

import java.security.MessageDigest;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CompleteRevocationRefs;
import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.ESFAttributes;
import org.bouncycastle.asn1.esf.OcspIdentifier;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SigningMaterial;

/**
 * CAdES-C seviyesinde unsigned attribute eklemesi (ETSI TS 101 733 §6.2):
 * <ul>
 *   <li>{@code id-aa-ets-certificateRefs} — tam sertifika referansları</li>
 *   <li>{@code id-aa-ets-revocationRefs} — tam iptal verisi referansları</li>
 * </ul>
 *
 * <p>DSS 6.3'ün baseline-LT seviyesi yalnızca yeni format
 * (SignedData.certificates / .crls) üretiyor; ancak Türk KamuSM / TÜBİTAK ESYA
 * doğrulayıcısı eski {@code id-aa-ets-*Refs} attribute'larını bekliyor. Bu sınıf,
 * baseline-LT çıktısının üstüne refs attribute'larını BouncyCastle ile elle ekler.</p>
 *
 * <p>{@link CAdESLevelXL} bu sınıfı extend eder ve aynı pasta üzerine
 * cert-values + revocation-values ekler; {@link CAdESLevelA} ise XL'in üstüne
 * archive-time-stamp-v2 koyar (XAdES override hierarşisiyle paralel mimari).</p>
 */
public class CAdESLevelC {

    private static final Logger LOGGER = LoggerFactory.getLogger(CAdESLevelC.class);

    protected final CertificateVerifier certificateVerifier;

    public CAdESLevelC(CertificateVerifier certificateVerifier) {
        this.certificateVerifier = certificateVerifier;
    }

    /**
     * Baseline-LT çıktısına C seviyesindeki refs attribute'larını ekler.
     */
    public CMSSignedData extend(CMSSignedData signedData,
                                SigningMaterial material,
                                DigestAlgorithm digestAlgorithm) {
        try {
            Context ctx = buildContext(signedData, material);
            Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<>();
            putRefsAttributes(attrs, ctx, digestAlgorithm);
            CMSSignedData result = CadesUtil.mergeUnsignedAttributes(
                    signedData, new AttributeTable(attrs));
            LOGGER.info("CAdES-C uzantısı eklendi (cert-refs + revoc-refs). "
                            + "TSA cert: {}, toplam CRL: {}, toplam OCSP: {}",
                    ctx.tsaCerts.size(), ctx.revocation.getCrls().size(),
                    ctx.revocation.getOcsps().size());
            return result;
        } catch (Exception ex) {
            throw new SignatureException("CADES_C_EXT_ERROR",
                    "CAdES-C (refs) uzantısı eklenemedi", ex);
        }
    }

    // ------------------------------------------------------------------
    // Protected pipeline — alt sınıflarla paylaşılır.
    // ------------------------------------------------------------------

    /**
     * Refs ve values arasında paylaşılan bağlam (TSA sertifikaları, dedup
     * cert listesi, birleştirilmiş revocation kümesi). Bir kez hesaplanıp
     * hem C hem de XL adımlarında kullanılır.
     */
    protected static final class Context {
        final Set<CertificateToken> tsaCerts;
        final Map<String, X509Certificate> uniqueCerts;
        final CadesUtil.CadesRevocationData revocation;

        Context(Set<CertificateToken> tsaCerts,
                Map<String, X509Certificate> uniqueCerts,
                CadesUtil.CadesRevocationData revocation) {
            this.tsaCerts = tsaCerts;
            this.uniqueCerts = uniqueCerts;
            this.revocation = revocation;
        }
    }

    /** Mevcut CMS'ten TSA sertifikalarını çıkartır, signer chain için revocation toplar ve dedup uniqueCerts hazırlar. */
    protected Context buildContext(CMSSignedData signedData, SigningMaterial material) throws Exception {
        Set<CertificateToken> tsaCerts = CadesUtil.extractTimestampCerts(signedData);

        // Revocation refs/values yalnızca signer chain için toplanır. DSS
        // CMSDocumentAnalyzer + ValidationData üzerinden — XAdESLevelC ile
        // birebir aynı pattern. TSA cert revocation'ı dahil olmaz (signature
        // timestamps temizleniyor → MA3 referans çıktısıyla uyumlu).
        CadesUtil.CadesRevocationData revocation =
                CadesUtil.collectRevocation(signedData, certificateVerifier);

        // Signer sertifikası SigningCertificateV2 ile zaten kapsanıyor ve ESYA
        // X-Long modunda cert-refs içinde de signer'ı ARAMIYOR — MA3 API
        // çıktısında signer cert-refs'te yok, sadece CA zinciri + TSA sertifikaları
        // var. Signer'ı eklediğimizde ESYA zincir görüntüsünü kırıyor.
        // Root sertifikası (self-signed) ETSI TS 101 733 6.2.1 gereği cert-refs'e
        // DAHİL edilir; MA3 de root'u ekliyor.
        List<X509Certificate> chain = material.getCertificateChain();
        Map<String, X509Certificate> unique = new LinkedHashMap<>();
        for (int i = 1; i < chain.size(); i++) {
            X509Certificate cert = chain.get(i);
            unique.put(CadesUtil.certKey(cert), cert);
        }
        for (CertificateToken token : tsaCerts) {
            X509Certificate cert = token.getCertificate();
            unique.putIfAbsent(CadesUtil.certKey(cert), cert);
        }

        return new Context(tsaCerts, unique, revocation);
    }

    /**
     * Refs attribute'larını ({@code certificateRefs}, {@code revocationRefs})
     * verilen tabloya ekler. Alt sınıflar (XL) aynı tabloya values ekleyebilir.
     */
    protected void putRefsAttributes(Hashtable<ASN1ObjectIdentifier, Attribute> attrs,
                                     Context ctx,
                                     DigestAlgorithm digestAlgorithm) throws Exception {
        AlgorithmIdentifier digestAlgId =
                new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlgorithm.getOid()));
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm.getJavaName());

        if (!ctx.uniqueCerts.isEmpty()) {
            ASN1EncodableVector certRefs = new ASN1EncodableVector();
            for (X509Certificate cert : ctx.uniqueCerts.values()) {
                byte[] hash = md.digest(cert.getEncoded());
                certRefs.add(new OtherCertID(digestAlgId, hash, CadesUtil.buildIssuerSerial(cert)));
            }
            attrs.put(ESFAttributes.certificateRefs,
                    new Attribute(ESFAttributes.certificateRefs,
                            new DERSet(new DERSequence(certRefs))));
        }

        if (ctx.revocation != null && !ctx.revocation.isEmpty()) {
            // Her revocation değeri (OCSP/CRL) kendi CrlOcspRef'ine sarılır.
            // MA3 API'nin çıktısında her entry ayrı CrlOcspRef olarak yer alıyor;
            // tek CrlOcspRef içinde hepsini birleştirince ESYA doğrulayıcısı
            // zincir görüntüsünü kırıyor. OCSP entry'leri önce, CRL entry'leri
            // sonra sıralanır.
            List<CrlOcspRef> refs = new ArrayList<>();

            for (BasicOCSPResp basic : ctx.revocation.getOcsps()) {
                OcspResponsesID ocspRef = buildOcspRef(basic, digestAlgId, md);
                OcspListID ocspListId = new OcspListID(new OcspResponsesID[]{ocspRef});
                refs.add(new CrlOcspRef(null, ocspListId, null));
            }
            for (X509CRL crl : ctx.revocation.getCrls()) {
                CrlValidatedID crlRef = buildCrlRef(crl, digestAlgId, md);
                CrlListID crlListId = new CrlListID(new CrlValidatedID[]{crlRef});
                refs.add(new CrlOcspRef(crlListId, null, null));
            }

            if (!refs.isEmpty()) {
                CompleteRevocationRefs completeRevocRefs =
                        new CompleteRevocationRefs(refs.toArray(new CrlOcspRef[0]));
                attrs.put(ESFAttributes.revocationRefs,
                        new Attribute(ESFAttributes.revocationRefs,
                                new DERSet(completeRevocRefs)));
            }
        }
    }

    // ------------------------------------------------------------------
    // BC ASN.1 helpers (refs build)
    // ------------------------------------------------------------------

    private CrlValidatedID buildCrlRef(X509CRL crl,
                                       AlgorithmIdentifier digestAlgId,
                                       MessageDigest md) throws Exception {
        byte[] encoded = crl.getEncoded();
        byte[] hash = md.digest(encoded);
        OtherHash otherHash = new OtherHash(
                new OtherHashAlgAndValue(digestAlgId, new DEROctetString(hash)));
        X500Name issuer = X500Name.getInstance(crl.getIssuerX500Principal().getEncoded());
        org.bouncycastle.asn1.ASN1UTCTime issuedTime =
                new org.bouncycastle.asn1.ASN1UTCTime(crl.getThisUpdate());

        // ETSI TS 101 733: CrlIdentifier.crlNumber is OPTIONAL, but ESYA
        // doğrulayıcısı CRL referansını CRL değeri ile eşleştirmek için
        // crlNumber'ı kullanıyor. CRL'in X509v3 "CRL Number" extension
        // değerinden çıkarıp ekliyoruz; yoksa referans paneli boş kalıyor.
        java.math.BigInteger crlNumber = CadesUtil.extractCrlNumber(crl);
        CrlIdentifier crlId = crlNumber != null
                ? new CrlIdentifier(issuer, issuedTime, crlNumber)
                : new CrlIdentifier(issuer, issuedTime);
        return new CrlValidatedID(otherHash, crlId);
    }

    private OcspResponsesID buildOcspRef(BasicOCSPResp basic,
                                         AlgorithmIdentifier digestAlgId,
                                         MessageDigest md) throws Exception {
        BasicOCSPResponse bcResp = BasicOCSPResponse.getInstance(basic.getEncoded());
        ResponseData rd = ResponseData.getInstance(bcResp.getTbsResponseData());
        OcspIdentifier ocspId = new OcspIdentifier(rd.getResponderID(), rd.getProducedAt());
        byte[] hash = md.digest(basic.getEncoded());
        OtherHash otherHash = new OtherHash(
                new OtherHashAlgAndValue(digestAlgId, new DEROctetString(hash)));
        return new OcspResponsesID(ocspId, otherHash);
    }
}
