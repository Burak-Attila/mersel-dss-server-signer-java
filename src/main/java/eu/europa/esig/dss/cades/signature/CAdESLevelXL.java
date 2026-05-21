package eu.europa.esig.dss.cades.signature;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.ESFAttributes;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SigningMaterial;

/**
 * CAdES-X-L (X-Long) seviyesinde unsigned attribute eklemesi (ETSI TS 101 733
 * §6.3): C seviyesindeki {@code certificateRefs} + {@code revocationRefs}
 * üstüne <b>aynı çağrıda</b> şunları ekler:
 * <ul>
 *   <li>{@code id-aa-ets-certValues} — sertifika zinciri değerleri</li>
 *   <li>{@code id-aa-ets-revocationValues} — CRL ve OCSP değerleri</li>
 * </ul>
 *
 * <p>Mevcut davranışı birebir korumak için 4 attribute tek bir
 * {@link AttributeTable} içinde toplanır ve <b>tek seferde</b>
 * {@code mergeUnsignedAttributes} ile imza zarfına işlenir; bu sayede
 * unsigned attribute'ların CMS içindeki sırası ve dolayısıyla ATSv2
 * mesaj imprintinin baytları değişmez.</p>
 *
 * @see CAdESLevelC
 * @see CAdESLevelA
 */
public class CAdESLevelXL extends CAdESLevelC {

    private static final Logger LOGGER = LoggerFactory.getLogger(CAdESLevelXL.class);

    public CAdESLevelXL(CertificateVerifier certificateVerifier) {
        super(certificateVerifier);
    }

    /**
     * Baseline-LT çıktısına X-Long seviyesindeki dört unsigned attribute'u
     * (cert-refs + revoc-refs + cert-values + revoc-values) tek atışta ekler.
     */
    @Override
    public CMSSignedData extend(CMSSignedData signedData,
                                SigningMaterial material,
                                DigestAlgorithm digestAlgorithm) {
        try {
            Context ctx = buildContext(signedData, material);
            Hashtable<ASN1ObjectIdentifier, Attribute> attrs = new Hashtable<>();
            putRefsAttributes(attrs, ctx, digestAlgorithm);
            putValuesAttributes(attrs, ctx, digestAlgorithm);
            CMSSignedData result = CadesUtil.mergeUnsignedAttributes(
                    signedData, new AttributeTable(attrs));
            LOGGER.info("CAdES-X-Long uzantısı eklendi (refs + values). "
                            + "TSA cert: {}, toplam CRL: {}, toplam OCSP: {}",
                    ctx.tsaCerts.size(), ctx.revocation.getCrls().size(),
                    ctx.revocation.getOcsps().size());
            return result;
        } catch (Exception ex) {
            throw new SignatureException("CADES_XLONG_EXT_ERROR",
                    "CAdES-X-Long uzantısı eklenemedi", ex);
        }
    }

    /**
     * X-L seviyesindeki values attribute'larını ({@code certValues},
     * {@code revocationValues}) verilen tabloya ekler.
     */
    protected void putValuesAttributes(Hashtable<ASN1ObjectIdentifier, Attribute> attrs,
                                       Context ctx,
                                       DigestAlgorithm digestAlgorithm) throws Exception {
        if (!ctx.uniqueCerts.isEmpty()) {
            ASN1EncodableVector certValues = new ASN1EncodableVector();
            for (X509Certificate cert : ctx.uniqueCerts.values()) {
                certValues.add(Certificate.getInstance(cert.getEncoded()));
            }
            attrs.put(ESFAttributes.certValues,
                    new Attribute(ESFAttributes.certValues,
                            new DERSet(new DERSequence(certValues))));
        }

        if (ctx.revocation != null && !ctx.revocation.isEmpty()) {
            CertificateList[] crlEntries = buildCertificateListEntries(ctx.revocation.getCrls());
            BasicOCSPResponse[] ocspEntries = buildBasicOcspEntries(ctx.revocation.getOcsps());
            RevocationValues revocationValues =
                    new RevocationValues(crlEntries, ocspEntries, null);

            attrs.put(ESFAttributes.revocationValues,
                    new Attribute(ESFAttributes.revocationValues,
                            new DERSet(revocationValues)));
        }
    }

    private CertificateList[] buildCertificateListEntries(List<X509CRL> crls) throws Exception {
        if (crls == null || crls.isEmpty()) {
            return null;
        }
        List<CertificateList> list = new ArrayList<>();
        for (X509CRL crl : crls) {
            list.add(CertificateList.getInstance(crl.getEncoded()));
        }
        return list.toArray(new CertificateList[0]);
    }

    private BasicOCSPResponse[] buildBasicOcspEntries(List<BasicOCSPResp> ocsps) throws Exception {
        if (ocsps == null || ocsps.isEmpty()) {
            return null;
        }
        List<BasicOCSPResponse> list = new ArrayList<>();
        for (BasicOCSPResp basic : ocsps) {
            list.add(BasicOCSPResponse.getInstance(basic.getEncoded()));
        }
        return list.toArray(new BasicOCSPResponse[0]);
    }
}
